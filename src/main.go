// Go GitHub Webhook handler (std library only)
//
// Features:
// - /ping : returns service state and server timestamp
// - POST /v1.0/github/event-logs/{signature-id}
//   * Fetch signature record from Supabase (PostgREST)
//   * Verify GitHub HMAC SHA256 signature using the secret from Supabase
//   * Save the payload to Firestore (Google) using Firestore REST API
//
// Environment variables required:
// SUPABASE_URL               -> e.g. https://xyz.supabase.co
// SUPABASE_KEY               -> service role key (used to read signature table)
// GOOGLE_SERVICE_ACCOUNT_JSON -> JSON content of service account (string). Alternatively set GOOGLE_SA_FILE and the program will read the file contents.
// FIREBASE_PROJECT_ID        -> Google Cloud project id for Firestore
// PORT                       -> optional, defaults to 8080
//
// Supabase assumptions:
// - There is a table named `signature` with columns: id (text/varchar), name (text), key (text)
// - We'll call PostgREST endpoint: {SUPABASE_URL}/rest/v1/signature?signature_id=eq.{id}&select=*
//
// Firestore: we write documents to collection named after signature.name
// Document structure: { payload: <raw json object>, received_at: <timestamp string> }
//
// NOTE: This program uses HTTP calls to Supabase and Firestore REST APIs only and uses only Go standard library.

// Go GitHub Webhook handler (std library only)
//
// Updated for Supabase table schema:
// id (signature_id), u_name (Firebase collection name), secret_key (HMAC key), created_at (timestamp)
//
// Features:
// - /ping : returns service state and server timestamp
// - POST /v1.0/github/event-logs/{signature-id}
//   * Fetch signature record from Supabase (PostgREST)
//   * Verify GitHub HMAC SHA256 signature using the secret_key from Supabase
//   * Save the payload to Firestore (Google) using Firestore REST API, collection name from u_name
//

package main

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"
)

// SignatureRecord represents row from supabase.signature table
type SignatureRecord struct {
	SignatureID string `json:"signature_id"`
	UName       string `json:"u_name"`
	SecretKey   string `json:"secret_key"`
	CreatedAt   string `json:"created_at"`
}

// ServiceAccount minimal fields parsed from JSON
type ServiceAccount struct {
	Type        string `json:"type"`
	ProjectID   string `json:"project_id"`
	PrivateKey  string `json:"private_key"`
	ClientEmail string `json:"client_email"`
	TokenURI    string `json:"token_uri"`
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	http.HandleFunc("/ping", pingHandler)
	http.HandleFunc("/v1.0/github/event-logs/", eventLogsRootHandler) // we will parse the rest

	addr := ":" + port
	log.Printf("Starting server on %s\n", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}

func pingHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	resp := map[string]interface{}{
		"status": "ok",
		"ts":     time.Now().UTC().Format(time.RFC3339),
	}
	writeJSON(w, http.StatusOK, resp)
}

// eventLogsRootHandler extracts signature-id from path and dispatches
func eventLogsRootHandler(w http.ResponseWriter, r *http.Request) {
	// path expected: /v1.0/github/event-logs/{signature-id}
	// trim prefix
	prefix := "/v1.0/github/event-logs/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	signatureID := strings.TrimPrefix(r.URL.Path, prefix)
	if signatureID == "" {
		w.WriteHeader(http.StatusBadRequest)
		_, err := fmt.Fprint(w, "missing signature id")
		if err != nil {
			return
		}
		return
	}

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	err := handleEventLog(w, r, signatureID)
	if err != nil {
		// handleEventLog already wrote response where applicable; log error
		log.Printf("handleEventLog error: %v", err)
	}
}

func handleEventLog(w http.ResponseWriter, r *http.Request, signatureID string) error {
	supabaseURL := os.Getenv("SUPABASE_URL")
	supabaseKey := os.Getenv("SUPABASE_KEY")
	if supabaseURL == "" || supabaseKey == "" {
		http.Error(w, "server misconfigured: missing SUPABASE_URL or SUPABASE_KEY", http.StatusInternalServerError)
		return errors.New("missing supabase config")
	}

	// Read full body
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			return
		}
	}(r.Body)

	// 1) Fetch signature from Supabase
	record, err := fetchSignatureFromSupabase(supabaseURL, supabaseKey, signatureID)
	if err != nil {
		// Return same error message when signature not found or key mismatch per user's requirement
		http.Error(w, "signature key wrong", http.StatusUnauthorized)
		return err
	}

	// if r.Header.Get("X-Hub-Signature-256") == "" {
	// 	http.Error(w, "signature key wrong", http.StatusUnauthorized)
	// 	var parts []string
	// 	for key, values := range r.Header {
	// 		// Join multiple values with comma
	// 		joined := strings.Join(values, ",")
	// 		parts = append(parts, fmt.Sprintf("%s=%s", key, joined))
	// 	}
	// 	return errors.New("errors: " + strings.Join(parts, "; "))
	// }

	// 2) Verify the GitHub signature header
	ok, err := verifyGithubSignature(r.Header.Get("X-Hub-Signature-256"), bodyBytes, record.SecretKey)
	if err != nil || !ok {
		http.Error(w, "signature key wrong", http.StatusUnauthorized)
		return errors.New("signature verification failed:" + err.Error())
	}

	// 3) Save to Firestore
	projectID := os.Getenv("FIREBASE_PROJECT_ID")
	if projectID == "" {
		http.Error(w, "server misconfigured: missing FIREBASE_PROJECT_ID", http.StatusInternalServerError)
		return errors.New("missing firebase project id")
	}

	saJSON := os.Getenv("GOOGLE_SERVICE_ACCOUNT_JSON")
	if saJSON == "" {
		// fallback to file path
		if path := os.Getenv("GOOGLE_SA_FILE"); path != "" {
			b, e := os.ReadFile(path)
			if e != nil {
				http.Error(w, "server misconfigured: cannot read service account file", http.StatusInternalServerError)
				return e
			}
			saJSON = string(b)
		}
	}
	if saJSON == "" {
		http.Error(w, "server misconfigured: missing GOOGLE_SERVICE_ACCOUNT_JSON", http.StatusInternalServerError)
		return errors.New("missing sa json")
	}

	var payload interface{}
	if len(bodyBytes) > 0 {
		// try to parse body as JSON object; if fails, store raw string
		if err := json.Unmarshal(bodyBytes, &payload); err != nil {
			payload = map[string]string{"raw": string(bodyBytes)}
		}
	} else {
		payload = map[string]string{"raw": ""}
	}

	if err := saveToFirestore(saJSON, projectID, record.UName, payload); err != nil {
		http.Error(w, "failed to save payload", http.StatusInternalServerError)
		return err
	}

	writeJSON(w, http.StatusOK, map[string]string{"result": "ok"})
	return nil
}

func fetchSignatureFromSupabase(supabaseURL, supabaseKey, signatureID string) (*SignatureRecord, error) {
	// Build url: {supabaseURL}/rest/v1/signature?signature_id=eq.{signatureID}&select=*
	u, err := url.Parse(supabaseURL)
	if err != nil {
		return nil, err
	}
	u.Path = path.Join(u.Path, "rest/v1/signature")
	q := u.Query()
	q.Set("signature_id", "eq."+signatureID)
	q.Set("select", "*")
	u.RawQuery = q.Encode()

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("apikey", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InljZ2ZmenR1amVsYW1keXZqbmJxIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTQwNzE5NjYsImV4cCI6MjA2OTY0Nzk2Nn0.DqbZvoyT7-tho_rWntG1QIrOT88yznEcP6BJ1_W-k38")
	req.Header.Set("Authorization", "Bearer "+"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InljZ2ZmenR1amVsYW1keXZqbmJxIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTQwNzE5NjYsImV4cCI6MjA2OTY0Nzk2Nn0.DqbZvoyT7-tho_rWntG1QIrOT88yznEcP6BJ1_W-k38")
	// supabase requires Accept: application/json
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("supabase returned status %d: %s", resp.StatusCode, string(b))
	}

	var arr []SignatureRecord
	if err := json.NewDecoder(resp.Body).Decode(&arr); err != nil {
		return nil, err
	}
	if len(arr) == 0 {
		return nil, fmt.Errorf("signature not found")
	}
	return &arr[0], nil
}

func verifyGithubSignature(headerSig string, body []byte, secret string) (bool, error) {
	// GitHub sends header: sha256=HEX
	if headerSig == "" {
		return false, errors.New("missing signature header")
	}
	parts := strings.SplitN(headerSig, "=", 2)
	if len(parts) != 2 {
		return false, errors.New("invalid signature header:" + headerSig)
	}
	algo := parts[0]
	hex := parts[1]
	fmt.Println(algo, hex)
	if algo != "sha256" && algo != "sha1" {
		// we expect sha256
		return false, errors.New("unexpected signature algorithm")
	}
	// compute HMAC-SHA256
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	expected := mac.Sum(nil)

	// parse provided hex
	provided, err := hexDecodeStringLenient(hex)
	if err != nil {
		return false, err
	}
	if len(provided) != len(expected) {
		return false, errors.New("invalid expected length")
	}
	if subtle.ConstantTimeCompare(provided, expected) == 1 {
		return true, nil
	}
	return false, errors.New("signature wrong:" + string(provided) + " + " + string(expected))
}

// hexDecodeStringLenient: accepts hex with or without leading 0x and allows upper/lower
func hexDecodeStringLenient(s string) ([]byte, error) {
	s = strings.TrimPrefix(s, "0x")
	// must be even length
	if len(s)%2 != 0 {
		// if odd, left-pad with 0
		s = "0" + s
	}
	dst := make([]byte, len(s)/2)
	for i := 0; i < len(dst); i++ {
		hi := fromHexChar(s[i*2])
		lo := fromHexChar(s[i*2+1])
		if hi < 0 || lo < 0 {
			return nil, fmt.Errorf("invalid hex")
		}
		dst[i] = byte(hi<<4 | lo)
	}
	return dst, nil
}

func fromHexChar(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c - 'a' + 10)
	case c >= 'A' && c <= 'F':
		return int(c - 'A' + 10)
	}
	return -1
}

func saveToFirestore(saJSON, projectID, collection string, payload interface{}) error {
	// Parse service account
	var sa ServiceAccount
	if err := json.Unmarshal([]byte(saJSON), &sa); err != nil {
		return fmt.Errorf("invalid service account json: %w", err)
	}
	if sa.TokenURI == "" {
		sa.TokenURI = "https://oauth2.googleapis.com/token"
	}

	// Build access token using JWT assertion
	accessToken, err := getAccessTokenFromSA(sa)
	if err != nil {
		return err
	}

	// Prepare Firestore REST API URL
	// POST https://firestore.googleapis.com/v1/projects/{projectID}/databases/(default)/documents/{collection}
	u := fmt.Sprintf("https://firestore.googleapis.com/v1/projects/%s/databases/(default)/documents/%s", url.PathEscape(projectID), url.PathEscape(collection))

	// Build Firestore document body
	doc := map[string]interface{}{
		"fields": map[string]interface{}{},
	}
	// Firestore expects typed fields, we'll store JSON string under "payload": { stringValue: ... }
	// and received_at as timestampValue
	fields := map[string]interface{}{
		"payload":     makeFirestoreValue(payload),
		"received_at": makeFirestoreValue(time.Now().UTC().Format(time.RFC3339)),
	}
	doc["fields"] = fields

	bodyBytes, _ := json.Marshal(doc)

	req, err := http.NewRequest("POST", u, strings.NewReader(string(bodyBytes)))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("firestore returned %d: %s", resp.StatusCode, string(b))
	}
	return nil
}

func makeFirestoreValue(v interface{}) map[string]interface{} {
	switch val := v.(type) {
	case string:
		return map[string]interface{}{"stringValue": v}
	case []byte:
		return map[string]interface{}{"bytesValue": base64.StdEncoding.EncodeToString(val)}
	case int, int32, int64:
		return map[string]interface{}{"integerValue": fmt.Sprintf("%v", val)}
	case float32, float64:
		return map[string]interface{}{"doubleValue": val}
	case bool:
		return map[string]interface{}{"booleanValue": val}
	case time.Time:
		return map[string]interface{}{"timestampValue": val.UTC().Format(time.RFC3339)}
	case map[string]interface{}:
		// nested map (objectValue)
		fields := make(map[string]interface{})
		for k, v2 := range val {
			fields[k] = makeFirestoreValue(v2)
		}
		return map[string]interface{}{"mapValue": map[string]interface{}{"fields": fields}}
	default:
		// fallback → simpan sebagai string JSON
		b, _ := json.Marshal(val)
		return map[string]interface{}{"stringValue": string(b)}
	}
}

func getAccessTokenFromSA(sa ServiceAccount) (string, error) {
	// Create JWT
	now := time.Now()
	exp := now.Add(time.Hour)

	header := map[string]string{"alg": "RS256", "typ": "JWT"}
	headerB, _ := json.Marshal(header)

	claims := map[string]interface{}{
		"iss":   sa.ClientEmail,
		"scope": "https://www.googleapis.com/auth/datastore",
		"aud":   sa.TokenURI,
		"exp":   exp.Unix(),
		"iat":   now.Unix(),
	}
	claimsB, _ := json.Marshal(claims)

	encoded := base64.RawURLEncoding.EncodeToString(headerB) + "." + base64.RawURLEncoding.EncodeToString(claimsB)

	// parse private key PEM
	privKey, err := parsePrivateKeyFromPEM(sa.PrivateKey)
	if err != nil {
		return "", err
	}

	hash := sha256.Sum256([]byte(encoded))
	sig, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, hash[:])
	if err != nil {
		return "", err
	}

	jwt := encoded + "." + base64.RawURLEncoding.EncodeToString(sig)

	// Exchange JWT for access token
	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
	form.Set("assertion", jwt)

	req, err := http.NewRequest("POST", sa.TokenURI, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("token endpoint returned %d: %s", resp.StatusCode, string(b))
	}
	var tokenResp struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", err
	}
	if tokenResp.AccessToken == "" {
		return "", errors.New("no access token in response")
	}
	return tokenResp.AccessToken, nil
}

func parsePrivateKeyFromPEM(pemStr string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("failed to parse PEM block")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err == nil {
		if rsaKey, ok := key.(*rsa.PrivateKey); ok {
			return rsaKey, nil
		}
	}
	// try PKCS1
	risakey, err2 := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err2 == nil {
		return risakey, nil
	}
	return nil, fmt.Errorf("parse private key errors: %v / %v", err, err2)
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
