package session

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/proishan11/open-agent-policy/engine/model"
)

// TokenValidator validates JWTs against multiple identity providers.
// It caches JWKS per binding trust anchor to avoid repeated fetches.
type TokenValidator struct {
	mu         sync.RWMutex
	jwksCache  map[string]*cachedJWKS
	wptReplay  map[string]time.Time
	client     *http.Client
	maxWPTSkew time.Duration
	maxWPTTTL  time.Duration
}

type cachedJWKS struct {
	jwks      *jose.JSONWebKeySet
	fetchedAt time.Time
}

// NewTokenValidator creates a multi-issuer token validator.
func NewTokenValidator() *TokenValidator {
	return &TokenValidator{
		jwksCache:  make(map[string]*cachedJWKS),
		wptReplay:  make(map[string]time.Time),
		client:     &http.Client{Timeout: 10 * time.Second},
		maxWPTSkew: 60 * time.Second,
		maxWPTTTL:  5 * time.Minute,
	}
}

// ValidationContext carries request evidence that can bind a runtime
// credential to the request where it is presented.
type ValidationContext struct {
	WorkloadProofToken string
	ProofContext       *ProofContext
}

type wimseIdentityClaims struct {
	CNF *struct {
		JWK jose.JSONWebKey `json:"jwk"`
	} `json:"cnf,omitempty"`
}

type wimseProofClaims struct {
	WTH string            `json:"wth"`
	ATH string            `json:"ath,omitempty"`
	TTH string            `json:"tth,omitempty"`
	OTH map[string]string `json:"oth,omitempty"`
}

// ValidateAgainstBindings validates a JWT against a set of identity bindings.
// It tries each binding: fetches the binding's issuer JWKS, verifies the JWT
// signature, validates standard claims, and checks the subject match.
// Returns nil if the token matches any binding.
func (v *TokenValidator) ValidateAgainstBindings(
	ctx context.Context,
	rawToken string,
	bindings []model.IdentityBinding,
	validation ValidationContext,
) error {
	parsed, err := jwt.ParseSigned(rawToken, supportedSignatureAlgorithms())
	if err != nil {
		return fmt.Errorf("parse token: %w", err)
	}

	// Try each binding's issuer JWKS to verify the token
	var lastErr error
	for _, binding := range bindings {
		if err := v.tryBinding(ctx, rawToken, parsed, binding, validation); err != nil {
			lastErr = err
			continue
		}
		return nil // success
	}

	if lastErr != nil {
		return fmt.Errorf("no matching identity binding: %w", lastErr)
	}
	return fmt.Errorf("no matching identity binding")
}

// tryBinding attempts to validate the parsed JWT against a single identity binding.
func (v *TokenValidator) tryBinding(
	ctx context.Context,
	rawToken string,
	parsed *jwt.JSONWebToken,
	binding model.IdentityBinding,
	validation ValidationContext,
) error {
	if !supportedBindingType(binding.Type) {
		return fmt.Errorf("unsupported identity binding type %q", binding.Type)
	}

	// 1. Fetch JWKS for the binding's issuer or explicit trust anchor.
	jwks, err := v.getJWKS(ctx, binding)
	if err != nil {
		return fmt.Errorf("fetch jwks for %s: %w", binding.Issuer, err)
	}

	// 2. Find matching signing keys
	matchKeys := findKeysFromJWKS(parsed, jwks)
	if len(matchKeys) == 0 {
		return fmt.Errorf("no matching signing key for issuer %s", binding.Issuer)
	}

	// 3. Verify signature and extract claims
	var stdClaims jwt.Claims
	var customClaims map[string]interface{}
	var wimseClaims wimseIdentityClaims
	verified := false

	for _, key := range matchKeys {
		stdClaims = jwt.Claims{}
		customClaims = make(map[string]interface{})
		wimseClaims = wimseIdentityClaims{}
		if err := parsed.Claims(key, &stdClaims, &customClaims, &wimseClaims); err != nil {
			continue
		}
		verified = true
		break
	}
	if !verified {
		return fmt.Errorf("signature verification failed for issuer %s", binding.Issuer)
	}

	if stdClaims.Expiry == nil {
		return fmt.Errorf("token missing exp claim")
	}
	if binding.Type == "spiffe" {
		if binding.Audience == "" {
			return fmt.Errorf("spiffe binding requires audience")
		}
		if len(stdClaims.Audience) == 0 {
			return fmt.Errorf("spiffe jwt-svid missing aud claim")
		}
	}
	if binding.Type == "wimse" {
		if err := requireJWTType(parsed, "wit+jwt"); err != nil {
			return fmt.Errorf("wimse wit type: %w", err)
		}
		if wimseClaims.CNF == nil || wimseClaims.CNF.JWK.Key == nil {
			return fmt.Errorf("wimse wit missing cnf.jwk")
		}
		if wimseClaims.CNF.JWK.Algorithm == "" {
			return fmt.Errorf("wimse wit cnf.jwk missing alg")
		}
	}

	// 4. Validate standard claims (issuer, expiry, audience)
	expected := jwt.Expected{
		Issuer: binding.Issuer,
		Time:   time.Now(),
	}
	if binding.Audience != "" && binding.Type != "wimse" {
		expected.AnyAudience = jwt.Audience{binding.Audience}
	}
	if err := stdClaims.ValidateWithLeeway(expected, 60*time.Second); err != nil {
		return fmt.Errorf("claims validation: %w", err)
	}

	// 5. Match subject against binding
	azp, _ := customClaims["azp"].(string)
	clientID, _ := customClaims["client_id"].(string)

	if !subjectMatches(binding.Subject, stdClaims.Subject, azp, clientID) {
		return fmt.Errorf("subject mismatch: binding expects %q, token has sub=%q azp=%q",
			binding.Subject, stdClaims.Subject, azp)
	}

	if binding.Type == "wimse" {
		if err := v.validateWIMSEProof(rawToken, binding, stdClaims, wimseClaims, validation); err != nil {
			return fmt.Errorf("wimse proof validation: %w", err)
		}
	}

	return nil
}

func supportedBindingType(bindingType string) bool {
	switch bindingType {
	case "oidc_client", "kubernetes_service_account", "spiffe", "wimse":
		return true
	default:
		return false
	}
}

func supportedSignatureAlgorithms() []jose.SignatureAlgorithm {
	return []jose.SignatureAlgorithm{
		jose.RS256, jose.RS384, jose.RS512,
		jose.ES256, jose.ES384, jose.ES512,
		jose.PS256, jose.PS384, jose.PS512,
		jose.EdDSA,
	}
}

// subjectMatches checks if any of the token's identity claims match the binding.
//
// Supported formats:
//   - Direct match against sub, azp, or client_id claims
//   - Prefixed: "client_id:support-agent" matches azp or client_id "support-agent"
//   - Workload IDs: SPIFFE and WIMSE identifiers match the JWT sub claim exactly
func subjectMatches(bindingSubject, tokenSub, azp, clientID string) bool {
	// Prefixed match: "client_id:support-agent"
	if strings.HasPrefix(bindingSubject, "client_id:") {
		expected := strings.TrimPrefix(bindingSubject, "client_id:")
		return expected == azp || expected == clientID
	}

	// Direct match
	if bindingSubject == tokenSub ||
		(azp != "" && bindingSubject == azp) ||
		(clientID != "" && bindingSubject == clientID) {
		return true
	}

	return false
}

func (v *TokenValidator) validateWIMSEProof(
	rawWIT string,
	binding model.IdentityBinding,
	witClaims jwt.Claims,
	wimseClaims wimseIdentityClaims,
	validation ValidationContext,
) error {
	if validation.WorkloadProofToken == "" {
		return fmt.Errorf("missing Workload-Proof-Token")
	}

	cnfKey := wimseClaims.CNF.JWK
	expectedAlg := jose.SignatureAlgorithm(cnfKey.Algorithm)
	if !asymmetricSignatureAlgorithm(expectedAlg) {
		return fmt.Errorf("unsupported cnf.jwk alg %q", cnfKey.Algorithm)
	}

	proof, err := jwt.ParseSigned(validation.WorkloadProofToken, supportedSignatureAlgorithms())
	if err != nil {
		return fmt.Errorf("parse Workload-Proof-Token: %w", err)
	}
	if len(proof.Headers) != 1 {
		return fmt.Errorf("Workload-Proof-Token must have exactly one signature")
	}
	if proof.Headers[0].Algorithm != cnfKey.Algorithm {
		return fmt.Errorf("Workload-Proof-Token alg %q does not match cnf.jwk alg %q", proof.Headers[0].Algorithm, cnfKey.Algorithm)
	}
	if err := requireJWTType(proof, "wpt+jwt"); err != nil {
		return fmt.Errorf("Workload-Proof-Token type: %w", err)
	}

	var proofStd jwt.Claims
	var proofClaims wimseProofClaims
	if err := proof.Claims(cnfKey.Key, &proofStd, &proofClaims); err != nil {
		return fmt.Errorf("verify Workload-Proof-Token: %w", err)
	}

	if proofStd.Expiry == nil {
		return fmt.Errorf("Workload-Proof-Token missing exp claim")
	}
	if proofStd.ID == "" {
		return fmt.Errorf("Workload-Proof-Token missing jti claim")
	}
	if time.Until(proofStd.Expiry.Time()) > v.maxWPTTTL {
		return fmt.Errorf("Workload-Proof-Token exp is too far in the future")
	}

	audiences := wimseProofAudiences(binding, validation.ProofContext)
	if len(audiences) == 0 {
		return fmt.Errorf("no acceptable WIMSE proof audience configured")
	}
	if err := proofStd.ValidateWithLeeway(jwt.Expected{
		AnyAudience: audiences,
		Time:        time.Now(),
	}, v.maxWPTSkew); err != nil {
		return fmt.Errorf("Workload-Proof-Token claims validation: %w", err)
	}

	if proofClaims.WTH == "" {
		return fmt.Errorf("Workload-Proof-Token missing wth claim")
	}
	if proofClaims.WTH != tokenHash(rawWIT) {
		return fmt.Errorf("Workload-Proof-Token wth claim does not match Workload-Identity-Token")
	}

	accessToken := ""
	if validation.ProofContext != nil {
		accessToken = validation.ProofContext.AccessToken
	}
	if accessToken != "" {
		if proofClaims.ATH == "" {
			return fmt.Errorf("Workload-Proof-Token missing ath claim for access token")
		}
		if proofClaims.ATH != tokenHash(accessToken) {
			return fmt.Errorf("Workload-Proof-Token ath claim does not match access token")
		}
	} else if proofClaims.ATH != "" {
		return fmt.Errorf("Workload-Proof-Token ath claim present without access token")
	}
	if proofClaims.TTH != "" {
		return fmt.Errorf("Workload-Proof-Token tth claim is not supported")
	}
	if len(proofClaims.OTH) > 0 {
		return fmt.Errorf("Workload-Proof-Token oth claim is not supported")
	}

	return v.markWPTJTI(witClaims.Subject, proofStd.ID, proofStd.Expiry.Time())
}

func asymmetricSignatureAlgorithm(alg jose.SignatureAlgorithm) bool {
	switch alg {
	case jose.RS256, jose.RS384, jose.RS512,
		jose.ES256, jose.ES384, jose.ES512,
		jose.PS256, jose.PS384, jose.PS512,
		jose.EdDSA:
		return true
	default:
		return false
	}
}

func requireJWTType(parsed *jwt.JSONWebToken, expected string) error {
	if len(parsed.Headers) != 1 {
		return fmt.Errorf("token must have exactly one signature")
	}
	got, _ := parsed.Headers[0].ExtraHeaders[jose.HeaderType].(string)
	if got == "" {
		return fmt.Errorf("missing typ header")
	}
	if got != expected && got != "application/"+expected {
		return fmt.Errorf("got typ %q, want %q", got, expected)
	}
	return nil
}

func wimseProofAudiences(binding model.IdentityBinding, proof *ProofContext) jwt.Audience {
	var audiences jwt.Audience
	if binding.Audience != "" {
		audiences = append(audiences, binding.Audience)
	}
	if proof != nil && proof.TargetURI != "" {
		for _, existing := range audiences {
			if existing == proof.TargetURI {
				return audiences
			}
		}
		audiences = append(audiences, proof.TargetURI)
	}
	return audiences
}

func tokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func (v *TokenValidator) markWPTJTI(subject, jti string, expiresAt time.Time) error {
	key := subject + "|" + jti
	now := time.Now()

	v.mu.Lock()
	defer v.mu.Unlock()

	for replayKey, replayExpiry := range v.wptReplay {
		if now.After(replayExpiry.Add(v.maxWPTSkew)) {
			delete(v.wptReplay, replayKey)
		}
	}
	if replayExpiry, ok := v.wptReplay[key]; ok && now.Before(replayExpiry.Add(v.maxWPTSkew)) {
		return fmt.Errorf("Workload-Proof-Token jti has already been used")
	}
	v.wptReplay[key] = expiresAt
	return nil
}

// --- JWKS management ---

func (v *TokenValidator) getJWKS(ctx context.Context, binding model.IdentityBinding) (*jose.JSONWebKeySet, error) {
	cacheKey := bindingCacheKey(binding)

	v.mu.RLock()
	cached, ok := v.jwksCache[cacheKey]
	v.mu.RUnlock()

	if ok && time.Since(cached.fetchedAt) < 1*time.Hour {
		return cached.jwks, nil
	}

	jwksURLs, err := jwksURLsForBinding(ctx, v.client, binding)
	if err != nil && len(jwksURLs) == 0 {
		return nil, err
	}

	var fetchErrs []string
	for _, jwksURL := range jwksURLs {
		jwks, err := fetchJWKS(ctx, v.client, jwksURL)
		if err != nil {
			fetchErrs = append(fetchErrs, err.Error())
			continue
		}
		jwks, err = normalizeJWKSForBinding(binding, jwks)
		if err != nil {
			fetchErrs = append(fetchErrs, err.Error())
			continue
		}

		v.mu.Lock()
		v.jwksCache[cacheKey] = &cachedJWKS{jwks: jwks, fetchedAt: time.Now()}
		v.mu.Unlock()

		return jwks, nil
	}

	return nil, fmt.Errorf("no jwks endpoint succeeded for issuer %s: %s", binding.Issuer, strings.Join(fetchErrs, "; "))
}

func bindingCacheKey(binding model.IdentityBinding) string {
	return binding.Type + "|" + binding.Issuer + "|" + binding.JWKSURI
}

func jwksURLsForBinding(ctx context.Context, client *http.Client, binding model.IdentityBinding) ([]string, error) {
	var urls []string
	if binding.JWKSURI != "" {
		urls = appendUniqueURL(urls, binding.JWKSURI)
		return urls, nil
	}

	jwksURL, err := discoverJWKS(ctx, client, binding.Issuer)
	if err == nil {
		urls = appendUniqueURL(urls, jwksURL)
	}

	issuer := strings.TrimSuffix(binding.Issuer, "/")
	switch binding.Type {
	case "oidc_client", "kubernetes_service_account", "wimse":
		urls = appendUniqueURL(urls, issuer+"/.well-known/jwks.json")
		urls = appendUniqueURL(urls, issuer+"/protocol/openid-connect/certs")
	case "spiffe":
		urls = appendUniqueURL(urls, issuer+"/.well-known/jwks.json")
	}

	if len(urls) == 0 && err != nil {
		return nil, fmt.Errorf("discover jwks for %s: %w", binding.Issuer, err)
	}
	return urls, nil
}

func appendUniqueURL(urls []string, candidate string) []string {
	if candidate == "" {
		return urls
	}
	for _, existing := range urls {
		if existing == candidate {
			return urls
		}
	}
	return append(urls, candidate)
}

func fetchJWKS(ctx context.Context, client *http.Client, jwksURL string) (*jose.JSONWebKeySet, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", jwksURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", jwksURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks endpoint %s returned %d", jwksURL, resp.StatusCode)
	}

	var jwks jose.JSONWebKeySet
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("decode jwks: %w", err)
	}

	return &jwks, nil
}

func normalizeJWKSForBinding(binding model.IdentityBinding, jwks *jose.JSONWebKeySet) (*jose.JSONWebKeySet, error) {
	if len(jwks.Keys) == 0 {
		return nil, fmt.Errorf("jwks has no keys")
	}
	if binding.Type != "spiffe" {
		return jwks, nil
	}

	filtered := jose.JSONWebKeySet{}
	for _, key := range jwks.Keys {
		if key.Use == "jwt-svid" {
			filtered.Keys = append(filtered.Keys, key)
		}
	}
	if len(filtered.Keys) == 0 {
		return nil, fmt.Errorf("spiffe bundle has no jwt-svid signing keys")
	}
	return &filtered, nil
}

func discoverJWKS(ctx context.Context, client *http.Client, issuerURL string) (string, error) {
	configURL := strings.TrimSuffix(issuerURL, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, "GET", configURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("discovery returned %d", resp.StatusCode)
	}
	var config struct {
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return "", err
	}
	if config.JWKSURI == "" {
		return "", fmt.Errorf("jwks_uri not found in discovery")
	}
	return config.JWKSURI, nil
}

func findKeysFromJWKS(parsed *jwt.JSONWebToken, jwks *jose.JSONWebKeySet) []interface{} {
	var keys []interface{}
	// Match by key ID first
	for _, header := range parsed.Headers {
		if header.KeyID != "" {
			for _, k := range jwks.Key(header.KeyID) {
				keys = append(keys, k.Key)
			}
		}
	}
	// Fallback: match by algorithm
	if len(keys) == 0 {
		for _, header := range parsed.Headers {
			for _, k := range jwks.Keys {
				if string(k.Algorithm) == header.Algorithm {
					keys = append(keys, k.Key)
				}
			}
		}
	}
	return keys
}
