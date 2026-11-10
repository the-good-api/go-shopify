package goshopify

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	// ClientAssertionTypeJWTBearer is the OAuth 2.0 client_assertion_type required
	// by Shopify for Option 3 application-only access tokens (RFC 7523).
	ClientAssertionTypeJWTBearer = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

	// AppOnlyAssertionLifetimeSeconds is the lifetime of each single-use signed JWT
	// client assertion (Shopify allows up to 300s; 60s is Shopify's recommended default).
	AppOnlyAssertionLifetimeSeconds = 60

	// AppOnlyRenewBeforeMinSeconds and AppOnlyRenewBeforeJitterSeconds implement
	// Shopify's recommended 3-to-8 minute jittered renewal window before token expiry
	// so multiple instances do not renew simultaneously.
	AppOnlyRenewBeforeMinSeconds    = 180
	AppOnlyRenewBeforeJitterSeconds = 300
)

var (
	appOnlyMaxAttempts   = 3
	appOnlyRetryBackoff  = 250 * time.Millisecond
	appOnlyTokenCache    sync.Map // map[string]*AppOnlyToken (keyed by normalized shop domain)
	parsedAppOnlyKeyMap  sync.Map // map[string]*parsedAppOnlyKey (keyed by SHA-256 of config)
	validShopDomainRegex = regexp.MustCompile(`^[a-z0-9][a-z0-9\-]*\.myshopify\.com$`)
	appOnlyFlight        appOnlySingleFlight
)

// AppOnlyToken represents a cached short-lived (1-hour) Shopify Admin API access token
// obtained via the client_credentials grant with a signed JWT client assertion (Option 3).
type AppOnlyToken struct {
	Shop        string    `json:"shop"`
	AccessToken string    `json:"-"`
	Scope       string    `json:"scope"`
	ExpiresIn   int64     `json:"expires_in"`
	ObtainedAt  time.Time `json:"obtained_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	RenewAt     time.Time `json:"renew_at"`
}

type parsedAppOnlyKey struct {
	alg    string // "RS256" or "ES256"
	rsaKey *rsa.PrivateKey
	ecKey  *ecdsa.PrivateKey
}

type clientAssertionHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

type clientAssertionClaims struct {
	Iss string `json:"iss"`
	Sub string `json:"sub"`
	Aud string `json:"aud"`
	Iat int64  `json:"iat"`
	Exp int64  `json:"exp"`
	Jti string `json:"jti"`
}

type appOnlyOAuthResponse struct {
	AccessToken string `json:"access_token"`
	Scope       string `json:"scope"`
	ExpiresIn   int64  `json:"expires_in"`
}

type appOnlyFlightCall struct {
	wg  sync.WaitGroup
	val *AppOnlyToken
	err error
}

type appOnlySingleFlight struct {
	mu sync.Mutex
	m  map[string]*appOnlyFlightCall
}

func (g *appOnlySingleFlight) Do(key string, fn func() (*AppOnlyToken, error)) (*AppOnlyToken, error) {
	g.mu.Lock()
	if g.m == nil {
		g.m = make(map[string]*appOnlyFlightCall)
	}
	if c, ok := g.m[key]; ok {
		g.mu.Unlock()
		c.wg.Wait()
		return c.val, c.err
	}
	c := new(appOnlyFlightCall)
	c.wg.Add(1)
	g.m[key] = c
	g.mu.Unlock()

	c.val, c.err = fn()
	c.wg.Done()

	g.mu.Lock()
	delete(g.m, key)
	g.mu.Unlock()

	return c.val, c.err
}

// NormalizeShopDomain normalizes a shop name or domain and validates that it
// strictly matches the anchored <subdomain>.myshopify.com hostname format,
// preventing SSRF or credential leakage to unanchored domains.
func NormalizeShopDomain(shopName string) (string, error) {
	trimmed := strings.TrimSpace(shopName)
	if trimmed == "" {
		return "", fmt.Errorf("invalid shopify shop domain: empty")
	}
	full := strings.ToLower(strings.TrimSpace(ShopFullName(trimmed)))
	if !validShopDomainRegex.MatchString(full) {
		return "", fmt.Errorf("invalid shopify shop domain: %q", shopName)
	}
	return full, nil
}

func (app App) effectiveKeyID() string {
	if k := strings.TrimSpace(app.KeyID); k != "" {
		return k
	}
	return strings.TrimSpace(os.Getenv("SHOPIFY_KEY_ID"))
}

func (app App) effectivePrivateKey() string {
	if k := strings.TrimSpace(app.PrivateKey); k != "" {
		return k
	}
	return strings.TrimSpace(os.Getenv("SHOPIFY_PRIVATE_KEY"))
}

func (app App) effectivePrivateKeyPath() string {
	if p := strings.TrimSpace(app.PrivateKeyPath); p != "" {
		return p
	}
	return strings.TrimSpace(os.Getenv("SHOPIFY_PRIVATE_KEY_PATH"))
}

func (app App) effectiveAppOnlyFlag() bool {
	if app.AppOnlyTokens {
		return true
	}
	v := strings.ToLower(strings.TrimSpace(os.Getenv("SHOPIFY_APP_ONLY_TOKENS")))
	return v == "true" || v == "1" || v == "yes"
}

// HasAppOnlyCredentials reports whether the App has a client ID (ApiKey),
// Key ID (KeyID / SHOPIFY_KEY_ID), and private key (PrivateKey / SHOPIFY_PRIVATE_KEY
// or PrivateKeyPath / SHOPIFY_PRIVATE_KEY_PATH) configured for Option 3 tokens.
func (app App) HasAppOnlyCredentials() bool {
	return strings.TrimSpace(app.ApiKey) != "" &&
		app.effectiveKeyID() != "" &&
		(app.effectivePrivateKey() != "" || app.effectivePrivateKeyPath() != "")
}

// IsAppOnlyTokensEnabled reports whether Option 3 application-only access tokens
// are enabled (via App.AppOnlyTokens or SHOPIFY_APP_ONLY_TOKENS=true) AND the
// required key credentials are present.
func (app App) IsAppOnlyTokensEnabled() bool {
	return app.effectiveAppOnlyFlag() && app.HasAppOnlyCredentials()
}

func (app App) loadParsedAppOnlyPrivateKey() (*parsedAppOnlyKey, error) {
	rawKey := app.effectivePrivateKey()
	keyPath := app.effectivePrivateKeyPath()
	if rawKey == "" && keyPath == "" {
		return nil, fmt.Errorf("shopify app-only private key is not configured (set SHOPIFY_PRIVATE_KEY or SHOPIFY_PRIVATE_KEY_PATH)")
	}

	sum := sha256.Sum256([]byte(rawKey + "|" + keyPath))
	cacheKey := hex.EncodeToString(sum[:])
	if cached, ok := parsedAppOnlyKeyMap.Load(cacheKey); ok {
		return cached.(*parsedAppOnlyKey), nil
	}

	if rawKey == "" && keyPath != "" {
		b, err := readKeyFileWithRootFallback(keyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read SHOPIFY_PRIVATE_KEY_PATH: %w", err)
		}
		rawKey = strings.TrimSpace(string(b))
	}

	parsed, err := parsePrivateKeyPEM(rawKey)
	if err != nil {
		return nil, err
	}
	parsedAppOnlyKeyMap.Store(cacheKey, parsed)
	return parsed, nil
}

func readKeyFileWithRootFallback(keyPath string) ([]byte, error) {
	if b, err := os.ReadFile(keyPath); err == nil {
		return b, nil
	} else if filepath.IsAbs(keyPath) {
		return nil, err
	}
	dir, err := os.Getwd()
	if err == nil {
		for {
			if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
				if b, rErr := os.ReadFile(filepath.Join(dir, keyPath)); rErr == nil {
					return b, nil
				}
				break
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			dir = parent
		}
	}
	return os.ReadFile(keyPath)
}

func parsePrivateKeyPEM(raw string) (*parsedAppOnlyKey, error) {
	normalized := strings.TrimSpace(raw)
	if normalized == "" {
		return nil, fmt.Errorf("empty private key")
	}
	// Support literal \n in single-line .env or Cloud Run environment variables
	normalized = strings.ReplaceAll(normalized, `\n`, "\n")

	// Support base64-encoded PEM strings if no PEM header is present
	if !strings.Contains(normalized, "-----BEGIN") {
		if decoded, err := base64.StdEncoding.DecodeString(normalized); err == nil && strings.Contains(string(decoded), "-----BEGIN") {
			normalized = string(decoded)
		}
	}

	block, _ := pem.Decode([]byte(normalized))
	if block == nil {
		return nil, fmt.Errorf("invalid PEM block in Shopify app-only private key")
	}

	// Try PKCS#8 first, then PKCS#1 RSA, then SEC1 EC
	if keyIfc, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		switch k := keyIfc.(type) {
		case *rsa.PrivateKey:
			return validateRSAKey(k)
		case *ecdsa.PrivateKey:
			return validateECKey(k)
		default:
			return nil, fmt.Errorf("unsupported PKCS#8 private key type %T: use RSA (2048-8192 bits) or EC P-256", keyIfc)
		}
	}
	if rsaKey, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return validateRSAKey(rsaKey)
	}
	if ecKey, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return validateECKey(ecKey)
	}

	return nil, fmt.Errorf("failed to parse Shopify app-only private key: use RSA (RS256) or EC P-256 (ES256) PEM")
}

func validateRSAKey(k *rsa.PrivateKey) (*parsedAppOnlyKey, error) {
	if k == nil || k.N == nil {
		return nil, fmt.Errorf("nil RSA private key")
	}
	bits := k.N.BitLen()
	if bits < 2048 || bits > 8192 {
		return nil, fmt.Errorf("RSA private key size %d bits out of Shopify allowed range (2048-8192 bits)", bits)
	}
	return &parsedAppOnlyKey{
		alg:    "RS256",
		rsaKey: k,
	}, nil
}

func validateECKey(k *ecdsa.PrivateKey) (*parsedAppOnlyKey, error) {
	if k == nil || k.Curve != elliptic.P256() {
		return nil, fmt.Errorf("EC private key must use P-256 (prime256v1) curve for ES256")
	}
	return &parsedAppOnlyKey{
		alg:   "ES256",
		ecKey: k,
	}, nil
}

func newUUIDv4() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// CreateClientAssertion signs a single-use RFC 7523 JWT client assertion for one
// token request to shopName. A new assertion (with a fresh UUIDv4 jti) must be
// signed for every token request, including retries.
func (app App) CreateClientAssertion(shopName string) (string, error) {
	normalizedShop, err := NormalizeShopDomain(shopName)
	if err != nil {
		return "", err
	}
	clientID := strings.TrimSpace(app.ApiKey)
	if clientID == "" {
		return "", fmt.Errorf("shopify client_id (ApiKey) is required for client assertion")
	}
	keyID := app.effectiveKeyID()
	if keyID == "" {
		return "", fmt.Errorf("shopify key_id (SHOPIFY_KEY_ID) is required for client assertion")
	}
	pk, err := app.loadParsedAppOnlyPrivateKey()
	if err != nil {
		return "", err
	}

	now := time.Now().Unix()
	hdrBytes, err := json.Marshal(clientAssertionHeader{
		Alg: pk.alg,
		Kid: keyID,
	})
	if err != nil {
		return "", fmt.Errorf("failed to marshal client assertion header: %w", err)
	}

	claimsBytes, err := json.Marshal(clientAssertionClaims{
		Iss: clientID,
		Sub: clientID,
		Aud: fmt.Sprintf("https://%s/admin/oauth/access_token", normalizedShop),
		Iat: now,
		Exp: now + AppOnlyAssertionLifetimeSeconds,
		Jti: newUUIDv4(),
	})
	if err != nil {
		return "", fmt.Errorf("failed to marshal client assertion claims: %w", err)
	}

	signingInput := base64.RawURLEncoding.EncodeToString(hdrBytes) + "." + base64.RawURLEncoding.EncodeToString(claimsBytes)
	digest := sha256.Sum256([]byte(signingInput))

	var sig []byte
	switch pk.alg {
	case "RS256":
		sig, err = rsa.SignPKCS1v15(rand.Reader, pk.rsaKey, crypto.SHA256, digest[:])
		if err != nil {
			return "", fmt.Errorf("failed to sign RS256 client assertion: %w", err)
		}
	case "ES256":
		r, s, signErr := ecdsa.Sign(rand.Reader, pk.ecKey, digest[:])
		if signErr != nil {
			return "", fmt.Errorf("failed to sign ES256 client assertion: %w", signErr)
		}
		sig = make([]byte, 64)
		r.FillBytes(sig[0:32])
		s.FillBytes(sig[32:64])
	default:
		return "", fmt.Errorf("unsupported signing algorithm %q", pk.alg)
	}

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func randomRenewJitterSeconds() int64 {
	n, err := rand.Int(rand.Reader, big.NewInt(AppOnlyRenewBeforeJitterSeconds+1))
	if err != nil || n == nil {
		return AppOnlyRenewBeforeMinSeconds
	}
	return AppOnlyRenewBeforeMinSeconds + n.Int64()
}

func computeAppOnlyRenewAt(obtainedAt time.Time, expiresIn int64) time.Time {
	if expiresIn <= 0 {
		return obtainedAt
	}
	renewBefore := randomRenewJitterSeconds()
	renewAfter := expiresIn - renewBefore
	halfLifetime := expiresIn / 2
	if renewAfter < halfLifetime {
		renewAfter = halfLifetime
	}
	if renewAfter < 1 {
		renewAfter = 1
	}
	return obtainedAt.Add(time.Duration(renewAfter) * time.Second)
}

func (app App) oauthHTTPClient(fallbackTransport http.RoundTripper) *http.Client {
	if app.Client != nil && app.Client.Client != nil {
		return app.Client.Client
	}
	if fallbackTransport != nil {
		return &http.Client{
			Transport: fallbackTransport,
			Timeout:   30 * time.Second,
		}
	}
	return &http.Client{
		Timeout: 30 * time.Second,
	}
}

func (app App) postAppOnlyOAuthForm(ctx context.Context, normalizedShop string, form url.Values, fallbackTransport http.RoundTripper) (*appOnlyOAuthResponse, int, error) {
	endpoint := fmt.Sprintf("https://%s/admin/oauth/access_token", normalizedShop)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", UserAgent)

	resp, err := app.oauthHTTPClient(fallbackTransport).Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("shopify oauth request failed for %s: %w", normalizedShop, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("failed to read shopify oauth response for %s: %w", normalizedShop, err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet := strings.TrimSpace(string(body))
		if len(snippet) > 256 {
			snippet = snippet[:256] + "..."
		}
		return nil, resp.StatusCode, fmt.Errorf("shopify oauth error for %s (status %d): %s", normalizedShop, resp.StatusCode, snippet)
	}

	var tokenResp appOnlyOAuthResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, resp.StatusCode, fmt.Errorf("failed to decode shopify oauth response for %s: %w", normalizedShop, err)
	}
	if tokenResp.AccessToken == "" {
		return nil, resp.StatusCode, fmt.Errorf("shopify oauth response returned empty access_token for %s", normalizedShop)
	}
	return &tokenResp, resp.StatusCode, nil
}

// RequestAppOnlyAccessToken exchanges a newly signed JWT client assertion for a
// short-lived (~1 hour) application-only Admin API access token for shopName.
// Retries up to 3 attempts on 5xx / 429 / network errors, signing a brand-new assertion
// (fresh jti) on each attempt. Never retries non-429 4xx responses.
func (app App) RequestAppOnlyAccessToken(ctx context.Context, shopName string) (*AppOnlyToken, error) {
	return app.requestAppOnlyAccessTokenWithTransport(ctx, shopName, nil)
}

func (app App) requestAppOnlyAccessTokenWithTransport(ctx context.Context, shopName string, fallbackTransport http.RoundTripper) (*AppOnlyToken, error) {
	normalizedShop, err := NormalizeShopDomain(shopName)
	if err != nil {
		return nil, err
	}
	clientID := strings.TrimSpace(app.ApiKey)
	if clientID == "" {
		return nil, fmt.Errorf("shopify client_id (ApiKey) is required")
	}

	var lastErr error
	for attempt := 1; attempt <= appOnlyMaxAttempts; attempt++ {
		assertion, err := app.CreateClientAssertion(normalizedShop)
		if err != nil {
			return nil, err
		}

		// Per Shopify spec: do NOT send client_secret or scope in this request.
		form := url.Values{}
		form.Set("grant_type", "client_credentials")
		form.Set("client_id", clientID)
		form.Set("client_assertion_type", ClientAssertionTypeJWTBearer)
		form.Set("client_assertion", assertion)

		tokenResp, status, postErr := app.postAppOnlyOAuthForm(ctx, normalizedShop, form, fallbackTransport)
		if postErr == nil && tokenResp != nil {
			expiresIn := tokenResp.ExpiresIn
			if expiresIn <= 0 {
				return nil, fmt.Errorf("shopify app-only oauth response missing positive expires_in for %s", normalizedShop)
			}
			now := time.Now()
			return &AppOnlyToken{
				Shop:        normalizedShop,
				AccessToken: tokenResp.AccessToken,
				Scope:       tokenResp.Scope,
				ExpiresIn:   expiresIn,
				ObtainedAt:  now,
				ExpiresAt:   now.Add(time.Duration(expiresIn) * time.Second),
				RenewAt:     computeAppOnlyRenewAt(now, expiresIn),
			}, nil
		}

		lastErr = postErr
		if status >= 400 && status < 500 && status != http.StatusTooManyRequests {
			return nil, lastErr
		}
		if attempt < appOnlyMaxAttempts {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(attempt) * appOnlyRetryBackoff):
			}
		}
	}
	return nil, lastErr
}

// GetAppOnlyAccessToken returns a valid application-only access token for shopName,
// serving from the per-process cache while before RenewAt and deduplicating
// concurrent renewals per shop via singleflight.
func (app App) GetAppOnlyAccessToken(ctx context.Context, shopName string) (*AppOnlyToken, error) {
	return app.getAppOnlyAccessTokenWithTransport(ctx, shopName, nil)
}

func (app App) getAppOnlyAccessTokenWithTransport(ctx context.Context, shopName string, fallbackTransport http.RoundTripper) (*AppOnlyToken, error) {
	normalizedShop, err := NormalizeShopDomain(shopName)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	var currentCached *AppOnlyToken
	if raw, ok := appOnlyTokenCache.Load(normalizedShop); ok {
		if tok, ok := raw.(*AppOnlyToken); ok && tok != nil && tok.AccessToken != "" {
			if now.Before(tok.RenewAt) {
				cp := *tok
				return &cp, nil
			}
			currentCached = tok
		}
	}

	flightKey := "app_only:" + normalizedShop
	tok, err := appOnlyFlight.Do(flightKey, func() (*AppOnlyToken, error) {
		checkNow := time.Now()
		if raw, ok := appOnlyTokenCache.Load(normalizedShop); ok {
			if cached, ok := raw.(*AppOnlyToken); ok && cached != nil && cached.AccessToken != "" && checkNow.Before(cached.RenewAt) {
				return cached, nil
			}
		}

		reqCtx := ctx
		if reqCtx == nil {
			reqCtx = context.Background()
		}
		reqCtx, cancel := context.WithTimeout(reqCtx, 20*time.Second)
		defer cancel()

		minted, reqErr := app.requestAppOnlyAccessTokenWithTransport(reqCtx, normalizedShop, fallbackTransport)
		if reqErr != nil {
			nowAfterErr := time.Now()
			if currentCached != nil && nowAfterErr.Before(currentCached.ExpiresAt) {
				fallback := *currentCached
				nextTry := nowAfterErr.Add(15 * time.Second)
				if nextTry.After(fallback.ExpiresAt) {
					nextTry = fallback.ExpiresAt
				}
				fallback.RenewAt = nextTry
				appOnlyTokenCache.Store(normalizedShop, &fallback)
				log.Printf("[goshopify] App-only token proactive renewal failed for %s (%v); reusing current token until %s",
					normalizedShop, reqErr, fallback.ExpiresAt.UTC().Format(time.RFC3339))
				return &fallback, nil
			}
			return nil, reqErr
		}

		appOnlyTokenCache.Store(normalizedShop, minted)
		log.Printf("[goshopify] Minted application-only access token (Option 3) for shop %s (expires_at=%s)",
			normalizedShop, minted.ExpiresAt.UTC().Format(time.RFC3339))
		return minted, nil
	})
	if err != nil {
		return nil, err
	}
	cp := *tok
	return &cp, nil
}

// ForceRefreshAppOnlyAccessToken invalidates any cached application-only token for
// shopName and requests a brand-new token from Shopify immediately.
func (app App) ForceRefreshAppOnlyAccessToken(ctx context.Context, shopName string) (*AppOnlyToken, error) {
	normalizedShop, err := NormalizeShopDomain(shopName)
	if err != nil {
		return nil, err
	}
	appOnlyTokenCache.Delete(normalizedShop)
	tok, err := app.RequestAppOnlyAccessToken(ctx, normalizedShop)
	if err != nil {
		return nil, err
	}
	appOnlyTokenCache.Store(normalizedShop, tok)
	log.Printf("[goshopify] Force-minted application-only access token (Option 3) for shop %s (expires_at=%s)",
		normalizedShop, tok.ExpiresAt.UTC().Format(time.RFC3339))
	return tok, nil
}

// GetCachedAppOnlyToken returns a copy of the currently cached application-only
// token metadata for shopName if present and not yet expired.
func GetCachedAppOnlyToken(shopName string) *AppOnlyToken {
	normalizedShop, err := NormalizeShopDomain(shopName)
	if err != nil {
		return nil
	}
	if raw, ok := appOnlyTokenCache.Load(normalizedShop); ok {
		if tok, ok := raw.(*AppOnlyToken); ok && tok != nil && time.Now().Before(tok.ExpiresAt) {
			cp := *tok
			return &cp
		}
	}
	return nil
}

// InvalidateAppOnlyAccessToken evicts the cached application-only access token for shopName.
func (app App) InvalidateAppOnlyAccessToken(shopName string) {
	if normalizedShop, err := NormalizeShopDomain(shopName); err == nil {
		appOnlyTokenCache.Delete(normalizedShop)
	} else {
		appOnlyTokenCache.Delete(strings.ToLower(strings.TrimSpace(shopName)))
	}
}

// ClearAllAppOnlyTokenCaches clears all cached Option 3 tokens and parsed private keys (used in tests).
func ClearAllAppOnlyTokenCaches() {
	appOnlyTokenCache.Range(func(k, _ interface{}) bool {
		appOnlyTokenCache.Delete(k)
		return true
	})
	parsedAppOnlyKeyMap.Range(func(k, _ interface{}) bool {
		parsedAppOnlyKeyMap.Delete(k)
		return true
	})
}

type appOnlyTokenTransport struct {
	app  App
	base http.RoundTripper
}

func (t *appOnlyTokenTransport) baseRoundTripper() http.RoundTripper {
	if t.base != nil {
		return t.base
	}
	if http.DefaultTransport != nil {
		return http.DefaultTransport
	}
	return &http.Transport{}
}

func (t *appOnlyTokenTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	base := t.baseRoundTripper()

	if !t.app.IsAppOnlyTokensEnabled() || req.URL == nil || !strings.HasPrefix(req.URL.Path, "/admin/") || strings.HasPrefix(req.URL.Path, "/admin/oauth/") {
		return base.RoundTrip(req)
	}

	shopName, err := NormalizeShopDomain(req.URL.Hostname())
	if err != nil {
		return base.RoundTrip(req)
	}

	var bodyBytes []byte
	if req.Body != nil {
		bodyBytes, err = io.ReadAll(req.Body)
		_ = req.Body.Close()
		if err != nil {
			return nil, err
		}
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	}

	appTok, tokErr := t.app.getAppOnlyAccessTokenWithTransport(req.Context(), shopName, t.base)
	outReq := req.Clone(req.Context())
	if bodyBytes != nil {
		outReq.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	}
	if tokErr == nil && appTok != nil && appTok.AccessToken != "" {
		outReq.Header.Set("X-Shopify-Access-Token", appTok.AccessToken)
	}

	usedToken := outReq.Header.Get("X-Shopify-Access-Token")
	resp, err := base.RoundTrip(outReq)
	if err != nil || resp == nil {
		return resp, err
	}

	// Reactive 401 recovery: evict cached token, mint a fresh Option 3 token once, and replay once.
	if resp.StatusCode == http.StatusUnauthorized {
		t.app.InvalidateAppOnlyAccessToken(shopName)
		freshTok, freshErr := t.app.getAppOnlyAccessTokenWithTransport(req.Context(), shopName, t.base)
		if freshErr == nil && freshTok != nil && freshTok.AccessToken != "" && freshTok.AccessToken != usedToken {
			_ = resp.Body.Close()
			retryReq := outReq.Clone(req.Context())
			if bodyBytes != nil {
				retryReq.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			}
			retryReq.Header.Set("X-Shopify-Access-Token", freshTok.AccessToken)
			return base.RoundTrip(retryReq)
		}
	}

	return resp, nil
}

// WrapHTTPClient returns a shallow copy of cli whose Transport is wrapped with
// the Option 3 application-only token RoundTripper when IsAppOnlyTokensEnabled() is true.
// Safe to call multiple times (idempotent).
func (app App) WrapHTTPClient(cli *http.Client) *http.Client {
	if !app.IsAppOnlyTokensEnabled() {
		return cli
	}
	if cli == nil {
		cli = &http.Client{Timeout: time.Second * defaultHttpTimeout}
	}
	if existing, ok := cli.Transport.(*appOnlyTokenTransport); ok {
		// Already wrapped; update app config in case fields changed
		cloned := *cli
		cloned.Transport = &appOnlyTokenTransport{
			app:  app,
			base: existing.base,
		}
		return &cloned
	}
	cloned := *cli
	cloned.Transport = &appOnlyTokenTransport{
		app:  app,
		base: cli.Transport,
	}
	return &cloned
}
