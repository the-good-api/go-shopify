package goshopify

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jarcoal/httpmock"
)

func generateTestRSAPrivateKeyPEM(t *testing.T, bits int) (*rsa.PrivateKey, string) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("failed to marshal PKCS8 RSA key: %v", err)
	}
	pemBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkcs8Bytes,
	})
	return priv, string(pemBlock)
}

func generateTestECPrivateKeyPEM(t *testing.T, curve elliptic.Curve) (*ecdsa.PrivateKey, string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate EC key: %v", err)
	}
	der, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("failed to marshal EC key: %v", err)
	}
	pemBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: der,
	})
	return priv, string(pemBlock)
}

func TestCreateClientAssertionRS256AndES256(t *testing.T) {
	ClearAllAppOnlyTokenCaches()
	t.Cleanup(ClearAllAppOnlyTokenCaches)

	rsaPriv, rsaPEM := generateTestRSAPrivateKeyPEM(t, 2048)
	testApp := App{
		ApiKey:        "client-id-123",
		AppOnlyTokens: true,
		KeyID:         "kid-rsa-2026",
		PrivateKey:    rsaPEM,
	}

	jwtStr1, err := testApp.CreateClientAssertion("goodapi-code-test")
	if err != nil {
		t.Fatalf("CreateClientAssertion RS256 failed: %v", err)
	}
	jwtStr2, err := testApp.CreateClientAssertion("goodapi-code-test.myshopify.com")
	if err != nil {
		t.Fatalf("CreateClientAssertion RS256 second call failed: %v", err)
	}

	parts := strings.Split(jwtStr1, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 JWT parts, got %d", len(parts))
	}

	var hdr clientAssertionHeader
	hdrJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("failed to decode header: %v", err)
	}
	if err := json.Unmarshal(hdrJSON, &hdr); err != nil {
		t.Fatalf("failed to unmarshal header: %v", err)
	}
	if hdr.Alg != "RS256" || hdr.Kid != "kid-rsa-2026" {
		t.Fatalf("unexpected header: %+v", hdr)
	}

	var claims1, claims2 clientAssertionClaims
	claims1JSON, _ := base64.RawURLEncoding.DecodeString(parts[1])
	_ = json.Unmarshal(claims1JSON, &claims1)
	parts2 := strings.Split(jwtStr2, ".")
	claims2JSON, _ := base64.RawURLEncoding.DecodeString(parts2[1])
	_ = json.Unmarshal(claims2JSON, &claims2)

	if claims1.Iss != "client-id-123" || claims1.Sub != "client-id-123" {
		t.Fatalf("unexpected iss/sub: %+v", claims1)
	}
	if claims1.Aud != "https://goodapi-code-test.myshopify.com/admin/oauth/access_token" {
		t.Fatalf("unexpected aud: %s", claims1.Aud)
	}
	if claims1.Exp-claims1.Iat != AppOnlyAssertionLifetimeSeconds {
		t.Fatalf("expected 60s lifetime, got %d", claims1.Exp-claims1.Iat)
	}
	if claims1.Jti == "" || claims1.Jti == claims2.Jti {
		t.Fatalf("expected unique non-empty jti per assertion, got %q and %q", claims1.Jti, claims2.Jti)
	}

	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("failed to decode RS256 signature: %v", err)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(&rsaPriv.PublicKey, crypto.SHA256, digest[:], sigBytes); err != nil {
		t.Fatalf("RS256 signature verification failed: %v", err)
	}

	// Test ES256 (P-256)
	ecPriv, ecPEM := generateTestECPrivateKeyPEM(t, elliptic.P256())
	ecApp := App{
		ApiKey:        "client-id-ec",
		AppOnlyTokens: true,
		KeyID:         "kid-ec-2026",
		PrivateKey:    ecPEM,
	}
	ecJWT, err := ecApp.CreateClientAssertion("goodapi-code-test.myshopify.com")
	if err != nil {
		t.Fatalf("CreateClientAssertion ES256 failed: %v", err)
	}
	ecParts := strings.Split(ecJWT, ".")
	ecSig, err := base64.RawURLEncoding.DecodeString(ecParts[2])
	if err != nil || len(ecSig) != 64 {
		t.Fatalf("expected 64-byte ES256 signature, got len=%d err=%v", len(ecSig), err)
	}
	r := new(big.Int).SetBytes(ecSig[:32])
	s := new(big.Int).SetBytes(ecSig[32:])
	ecDigest := sha256.Sum256([]byte(ecParts[0] + "." + ecParts[1]))
	if !ecdsa.Verify(&ecPriv.PublicKey, ecDigest[:], r, s) {
		t.Fatalf("ES256 signature verification failed")
	}
}

func TestAppOnlyKeyValidationEdgeCases(t *testing.T) {
	ClearAllAppOnlyTokenCaches()
	t.Cleanup(ClearAllAppOnlyTokenCaches)

	// Invalid PEM
	badApp := App{ApiKey: "cid", KeyID: "kid", PrivateKey: "not-a-pem"}
	if _, err := badApp.CreateClientAssertion("goodapi-code-test.myshopify.com"); err == nil {
		t.Fatalf("expected error for invalid PEM")
	}

	// P-384 curve should be rejected (Shopify only allows P-256 for ES256)
	_, p384PEM := generateTestECPrivateKeyPEM(t, elliptic.P384())
	p384App := App{ApiKey: "cid", KeyID: "kid", PrivateKey: p384PEM}
	if _, err := p384App.CreateClientAssertion("goodapi-code-test.myshopify.com"); err == nil {
		t.Fatalf("expected error for P-384 EC key")
	}

	// Invalid shop domain should be rejected
	_, rsaPEM := generateTestRSAPrivateKeyPEM(t, 2048)
	validApp := App{ApiKey: "cid", KeyID: "kid", PrivateKey: rsaPEM}
	if _, err := validApp.CreateClientAssertion("evil.example.com/foo"); err == nil {
		t.Fatalf("expected error for invalid shop domain")
	}
}

func TestAppOnlyTokenExchangeCacheRetryAnd401Recovery(t *testing.T) {
	setup()
	defer teardown()
	ClearAllAppOnlyTokenCaches()
	t.Cleanup(ClearAllAppOnlyTokenCaches)

	origBackoff := appOnlyRetryBackoff
	appOnlyRetryBackoff = 5 * time.Millisecond
	defer func() { appOnlyRetryBackoff = origBackoff }()

	_, rsaPEM := generateTestRSAPrivateKeyPEM(t, 2048)

	// Write key to temp file to also test SHOPIFY_PRIVATE_KEY_PATH + env var discovery
	tmpDir := t.TempDir()
	keyFile := filepath.Join(tmpDir, "priv-test.pem")
	if err := os.WriteFile(keyFile, []byte(rsaPEM), 0600); err != nil {
		t.Fatalf("failed to write temp key file: %v", err)
	}

	t.Setenv("SHOPIFY_APP_ONLY_TOKENS", "true")
	t.Setenv("SHOPIFY_KEY_ID", "env-kid-2026")
	t.Setenv("SHOPIFY_PRIVATE_KEY_PATH", keyFile)

	var oauthCalls int32
	var seenJTIs sync.Map

	httpmock.RegisterResponder("POST", "https://fooshop.myshopify.com/admin/oauth/access_token",
		func(req *http.Request) (*http.Response, error) {
			callNum := atomic.AddInt32(&oauthCalls, 1)
			bodyBytes, _ := io.ReadAll(req.Body)
			vals, _ := url.ParseQuery(string(bodyBytes))

			if vals.Get("grant_type") != "client_credentials" {
				t.Errorf("expected grant_type=client_credentials, got %q", vals.Get("grant_type"))
			}
			if vals.Get("client_assertion_type") != ClientAssertionTypeJWTBearer {
				t.Errorf("unexpected client_assertion_type: %q", vals.Get("client_assertion_type"))
			}
			if vals.Get("client_secret") != "" || vals.Get("scope") != "" {
				t.Errorf("client_secret and scope must NOT be sent in Option 3 request")
			}
			assertion := vals.Get("client_assertion")
			parts := strings.Split(assertion, ".")
			if len(parts) == 3 {
				var claims clientAssertionClaims
				cb, _ := base64.RawURLEncoding.DecodeString(parts[1])
				_ = json.Unmarshal(cb, &claims)
				if _, dup := seenJTIs.LoadOrStore(claims.Jti, true); dup {
					t.Errorf("duplicate jti reused across token requests: %s", claims.Jti)
				}
			}

			// Simulate a transient 502 on the very first call to test retry with fresh jti
			if callNum == 1 {
				return httpmock.NewStringResponse(502, `{"error":"bad_gateway"}`), nil
			}
			if callNum == 2 {
				return httpmock.NewStringResponse(200, `{"access_token":"test_app_only_token_v1","scope":"read_products","expires_in":3600}`), nil
			}
			return httpmock.NewStringResponse(200, `{"access_token":"test_app_only_token_v2","scope":"read_products","expires_in":3600}`), nil
		})

	app.Client = client

	// 1. Test App.GetAccessToken with empty code (simulating Managed Install callback)
	tok, err := app.GetAccessToken("fooshop", "")
	if err != nil {
		t.Fatalf("App.GetAccessToken failed: %v", err)
	}
	if tok != "test_app_only_token_v1" {
		t.Fatalf("expected test_app_only_token_v1, got %q", tok)
	}
	if atomic.LoadInt32(&oauthCalls) != 2 {
		t.Fatalf("expected 2 OAuth calls (1st 502 + 2nd 200), got %d", oauthCalls)
	}

	// 2. Subsequent GetAppOnlyAccessToken should serve from cache without hitting OAuth
	cachedTok, err := app.GetAppOnlyAccessToken(context.Background(), "fooshop")
	if err != nil || cachedTok.AccessToken != "test_app_only_token_v1" {
		t.Fatalf("expected cached token test_app_only_token_v1, got %+v err=%v", cachedTok, err)
	}
	if atomic.LoadInt32(&oauthCalls) != 2 {
		t.Fatalf("expected 0 additional OAuth calls on cache hit, got %d total", oauthCalls)
	}

	// 3. Test NewClient + 401 auto-refresh and replay on Admin API request
	var apiCalls int32
	var receivedHeaders []string
	var receivedBodies []string
	httpmock.RegisterResponder("POST", "https://fooshop.myshopify.com/admin/api/9999-99/graphql.json",
		func(req *http.Request) (*http.Response, error) {
			n := atomic.AddInt32(&apiCalls, 1)
			receivedHeaders = append(receivedHeaders, req.Header.Get("X-Shopify-Access-Token"))
			b, _ := io.ReadAll(req.Body)
			receivedBodies = append(receivedBodies, string(b))
			if n == 1 {
				// Simulate expired/revoked token 401 on first attempt
				return httpmock.NewStringResponse(401, `{"errors":"[API] Invalid API key or access token"}`), nil
			}
			return httpmock.NewStringResponse(200, `{"data":{"shop":{"name":"goodapi-code-test"}}}`), nil
		})

	apiClient := app.NewClient("fooshop", "legacy_ignored_token", WithVersion(testApiVersion))
	httpmock.ActivateNonDefault(apiClient.Client)

	req, err := apiClient.NewRequest("POST", "admin/api/9999-99/graphql.json", map[string]string{"query": "{ shop { name } }"}, nil)
	if err != nil {
		t.Fatalf("NewRequest failed: %v", err)
	}
	var respData map[string]interface{}
	if err := apiClient.Do(req, &respData); err != nil {
		t.Fatalf("apiClient.Do failed after 401 recovery: %v", err)
	}

	if atomic.LoadInt32(&apiCalls) != 2 {
		t.Fatalf("expected 2 API calls (initial 401 + replay 200), got %d", apiCalls)
	}
	if receivedHeaders[0] != "test_app_only_token_v1" || receivedHeaders[1] != "test_app_only_token_v2" {
		t.Fatalf("expected headers [test_app_only_token_v1, test_app_only_token_v2], got %v", receivedHeaders)
	}
	if receivedBodies[0] == "" || receivedBodies[0] != receivedBodies[1] {
		t.Fatalf("expected request body to be preserved and replayed on 401 retry, got %v", receivedBodies)
	}
}
