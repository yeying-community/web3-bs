package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/golang-jwt/jwt/v5"
)

type challengeRecord struct {
	Challenge string `json:"challenge"`
	IssuedAt  int64  `json:"issuedAt"`
	ExpiresAt int64  `json:"expiresAt"`
}

type refreshRecord struct {
	Address   string
	ExpiresAt int64
}

type envelope struct {
	Code      int         `json:"code"`
	Message   string      `json:"message"`
	Data      interface{} `json:"data"`
	Timestamp int64       `json:"timestamp"`
}

type tokenClaims struct {
	Address string `json:"address"`
	Typ     string `json:"typ"`
	Sid     string `json:"sid,omitempty"`
	Jti     string `json:"jti,omitempty"`
	jwt.RegisteredClaims
}

type ucanCapability struct {
	Resource string `json:"resource"`
	Action   string `json:"action"`
}

type ucanRootProof struct {
	Type string           `json:"type"`
	Iss  string           `json:"iss"`
	Aud  string           `json:"aud"`
	Cap  []ucanCapability `json:"cap"`
	Exp  int64            `json:"exp"`
	Nbf  *int64           `json:"nbf,omitempty"`
	Siwe struct {
		Message   string `json:"message"`
		Signature string `json:"signature"`
	} `json:"siwe"`
}

type ucanStatement struct {
	Aud string           `json:"aud"`
	Cap []ucanCapability `json:"cap"`
	Exp int64            `json:"exp"`
	Nbf *int64           `json:"nbf,omitempty"`
}

type ucanPayload struct {
	Iss string            `json:"iss"`
	Aud string            `json:"aud"`
	Cap []ucanCapability  `json:"cap"`
	Exp int64             `json:"exp"`
	Nbf *int64            `json:"nbf,omitempty"`
	Prf []json.RawMessage `json:"prf"`
}

var (
	challenges   = make(map[string]challengeRecord)
	refreshStore = make(map[string]refreshRecord)
	lock         sync.Mutex
)

const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	n, err := r.ResponseWriter.Write(b)
	r.bytes += n
	return n, err
}

func nowMillis() int64 {
	return time.Now().UnixMilli()
}

func preview(value string) string {
	if value == "" {
		return ""
	}
	if len(value) <= 20 {
		return value
	}
	return value[:8] + "..." + value[len(value)-8:]
}

func summarizeCaps(caps []ucanCapability) []string {
	if len(caps) == 0 {
		return []string{}
	}
	out := make([]string, 0, len(caps))
	for _, cap := range caps {
		if cap.Resource != "" && cap.Action != "" {
			out = append(out, cap.Resource+":"+cap.Action)
		}
	}
	return out
}

func ok(data interface{}) envelope {
	return envelope{Code: 0, Message: "ok", Data: data, Timestamp: nowMillis()}
}

func fail(code int, message string) envelope {
	return envelope{Code: code, Message: message, Data: nil, Timestamp: nowMillis()}
}

func getenv(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}

func parseBoolEnv(key string) bool {
	value := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	return value == "1" || value == "true" || value == "yes"
}

func parseIntEnv(key string, fallback int64) int64 {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	parsed, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return fallback
	}
	return parsed
}

func allowedOriginSet(port int) map[string]struct{} {
	defaults := []string{
		fmt.Sprintf("http://127.0.0.1:%d", port),
		fmt.Sprintf("http://127.0.0.1:%d", port),
		"http://127.0.0.1:8000",
		"http://127.0.0.1:8000",
		"http://127.0.0.1:8001",
		"http://127.0.0.1:8001",
	}
	multiPorts := []int{3201, 3202, 3203, 3204}
	for _, p := range multiPorts {
		defaults = append(defaults, fmt.Sprintf("http://127.0.0.1:%d", p), fmt.Sprintf("http://127.0.0.1:%d", p))
	}
	value := getenv("CORS_ORIGINS", strings.Join(defaults, ","))
	set := make(map[string]struct{})
	for _, origin := range strings.Split(value, ",") {
		origin = strings.TrimSpace(origin)
		if origin != "" {
			set[origin] = struct{}{}
		}
	}
	return set
}

func writeJSON(w http.ResponseWriter, status int, payload envelope) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func randomHex(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func recoverAddress(message string, signature string) (string, error) {
	sig, err := hexutil.Decode(signature)
	if err != nil {
		return "", err
	}
	if len(sig) != 65 {
		return "", fmt.Errorf("invalid signature length")
	}
	if sig[64] >= 27 {
		sig[64] -= 27
	}

	hash := accounts.TextHash([]byte(message))
	pubKey, err := crypto.SigToPub(hash, sig)
	if err != nil {
		return "", err
	}
	return strings.ToLower(crypto.PubkeyToAddress(*pubKey).Hex()), nil
}

func base64UrlDecode(input string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(input)
}

func base58Decode(input string) ([]byte, error) {
	bytes := []byte{0}
	for _, r := range input {
		index := strings.IndexRune(base58Alphabet, r)
		if index < 0 {
			return nil, fmt.Errorf("invalid base58 character")
		}
		carry := index
		for i := 0; i < len(bytes); i++ {
			carry += int(bytes[i]) * 58
			bytes[i] = byte(carry & 0xff)
			carry >>= 8
		}
		for carry > 0 {
			bytes = append(bytes, byte(carry&0xff))
			carry >>= 8
		}
	}
	zeros := 0
	for zeros < len(input) && input[zeros] == '1' {
		zeros++
	}
	output := make([]byte, zeros+len(bytes))
	for i := 0; i < zeros; i++ {
		output[i] = 0
	}
	for i := 0; i < len(bytes); i++ {
		output[len(output)-1-i] = bytes[i]
	}
	return output, nil
}

func didKeyToPublicKey(did string) ([]byte, error) {
	if !strings.HasPrefix(did, "did:key:z") {
		return nil, fmt.Errorf("invalid did:key format")
	}
	decoded, err := base58Decode(strings.TrimPrefix(did, "did:key:z"))
	if err != nil {
		return nil, err
	}
	if len(decoded) < 3 || decoded[0] != 0xed || decoded[1] != 0x01 {
		return nil, fmt.Errorf("unsupported did:key type")
	}
	return decoded[2:], nil
}

func normalizeEpochMillis(value int64) int64 {
	if value == 0 {
		return 0
	}
	if value < 1e12 {
		return value * 1000
	}
	return value
}

func matchPattern(pattern, value string) bool {
	if pattern == "*" {
		return true
	}
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(value, strings.TrimSuffix(pattern, "*"))
	}
	return pattern == value
}

func capsAllow(available []ucanCapability, required []ucanCapability) bool {
	if len(available) == 0 {
		return false
	}
	for _, req := range required {
		matched := false
		for _, cap := range available {
			if matchPattern(cap.Resource, req.Resource) && matchPattern(cap.Action, req.Action) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

func extractUcanStatement(message string) (*ucanStatement, error) {
	lines := strings.Split(message, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToUpper(trimmed), "UCAN-AUTH") {
			jsonPart := strings.TrimSpace(strings.TrimPrefix(trimmed, "UCAN-AUTH"))
			jsonPart = strings.TrimSpace(strings.TrimPrefix(jsonPart, ":"))
			var statement ucanStatement
			if err := json.Unmarshal([]byte(jsonPart), &statement); err != nil {
				return nil, err
			}
			return &statement, nil
		}
	}
	return nil, fmt.Errorf("missing UCAN statement")
}

func verifyRootProof(root ucanRootProof) (ucanStatement, string, error) {
	if root.Type != "siwe" || root.Siwe.Message == "" || root.Siwe.Signature == "" {
		return ucanStatement{}, "", fmt.Errorf("invalid root proof")
	}
	recovered, err := recoverAddress(root.Siwe.Message, root.Siwe.Signature)
	if err != nil {
		return ucanStatement{}, "", err
	}
	iss := "did:pkh:eth:" + recovered
	if root.Iss != "" && root.Iss != iss {
		log.Printf("UCAN root issuer mismatch rootIss=%s recoveredIss=%s", root.Iss, iss)
		return ucanStatement{}, "", fmt.Errorf("root issuer mismatch")
	}

	statement, err := extractUcanStatement(root.Siwe.Message)
	if err != nil {
		return ucanStatement{}, "", err
	}

	aud := statement.Aud
	if aud == "" {
		aud = root.Aud
	}
	exp := normalizeEpochMillis(statement.Exp)
	if exp == 0 {
		exp = normalizeEpochMillis(root.Exp)
	}
	if aud == "" || exp == 0 || len(statement.Cap) == 0 && len(root.Cap) == 0 {
		log.Printf("UCAN root claims invalid aud=%s exp=%d capCount=%d", aud, exp, len(statement.Cap)+len(root.Cap))
		return ucanStatement{}, "", fmt.Errorf("invalid root claims")
	}
	if root.Aud != "" && root.Aud != aud {
		log.Printf("UCAN root audience mismatch rootAud=%s aud=%s", root.Aud, aud)
		return ucanStatement{}, "", fmt.Errorf("root audience mismatch")
	}

	cap := statement.Cap
	if len(cap) == 0 {
		cap = root.Cap
	}
	statement.Aud = aud
	statement.Exp = exp
	statement.Cap = cap
	if statement.Nbf == nil && root.Nbf != nil {
		nbf := normalizeEpochMillis(*root.Nbf)
		statement.Nbf = &nbf
	}

	nowMs := nowMillis()
	if statement.Nbf != nil && nowMs < *statement.Nbf {
		return ucanStatement{}, "", fmt.Errorf("root not active")
	}
	if nowMs > exp {
		return ucanStatement{}, "", fmt.Errorf("root expired")
	}

	log.Printf("UCAN root verified iss=%s aud=%s exp=%d nbf=%v caps=%v", iss, statement.Aud, statement.Exp, statement.Nbf, summarizeCaps(statement.Cap))
	return *statement, iss, nil
}

func decodeUcanToken(token string) (map[string]interface{}, ucanPayload, []byte, string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ucanPayload{}, nil, "", fmt.Errorf("invalid UCAN token")
	}
	headerBytes, err := base64UrlDecode(parts[0])
	if err != nil {
		return nil, ucanPayload{}, nil, "", err
	}
	payloadBytes, err := base64UrlDecode(parts[1])
	if err != nil {
		return nil, ucanPayload{}, nil, "", err
	}
	sig, err := base64UrlDecode(parts[2])
	if err != nil {
		return nil, ucanPayload{}, nil, "", err
	}

	var header map[string]interface{}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, ucanPayload{}, nil, "", err
	}
	var payload ucanPayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, ucanPayload{}, nil, "", err
	}
	return header, payload, sig, parts[0] + "." + parts[1], nil
}

func verifyUcanJws(token string) (ucanPayload, int64, error) {
	header, payload, sig, signingInput, err := decodeUcanToken(token)
	if err != nil {
		return ucanPayload{}, 0, err
	}
	if alg, ok := header["alg"].(string); ok && alg != "EdDSA" {
		return ucanPayload{}, 0, fmt.Errorf("unsupported UCAN alg")
	}

	rawKey, err := didKeyToPublicKey(payload.Iss)
	if err != nil {
		return ucanPayload{}, 0, err
	}
	if !ed25519.Verify(rawKey, []byte(signingInput), sig) {
		return ucanPayload{}, 0, fmt.Errorf("invalid UCAN signature")
	}

	exp := normalizeEpochMillis(payload.Exp)
	nbf := int64(0)
	if payload.Nbf != nil {
		nbf = normalizeEpochMillis(*payload.Nbf)
	}
	nowMs := nowMillis()
	if nbf != 0 && nowMs < nbf {
		return ucanPayload{}, 0, fmt.Errorf("UCAN not active")
	}
	if exp != 0 && nowMs > exp {
		return ucanPayload{}, 0, fmt.Errorf("UCAN expired")
	}

	log.Printf("UCAN JWS verified iss=%s aud=%s exp=%d nbf=%d caps=%v", payload.Iss, payload.Aud, exp, nbf, summarizeCaps(payload.Cap))
	return payload, exp, nil
}

func verifyProofChain(currentDid string, required []ucanCapability, requiredExp int64, proofs []json.RawMessage) (string, error) {
	if len(proofs) == 0 {
		return "", fmt.Errorf("missing UCAN proof chain")
	}
	log.Printf("UCAN proof chain currentDid=%s requiredExp=%d proofs=%d requiredCaps=%v", currentDid, requiredExp, len(proofs), summarizeCaps(required))
	first := proofs[0]
	if len(first) > 0 && first[0] == '"' {
		var token string
		if err := json.Unmarshal(first, &token); err != nil {
			return "", err
		}
		payload, proofExp, err := verifyUcanJws(token)
		if err != nil {
			return "", err
		}
		if payload.Aud != currentDid {
			return "", fmt.Errorf("UCAN audience mismatch expected=%s got=%s", currentDid, payload.Aud)
		}
		if !capsAllow(payload.Cap, required) {
			return "", fmt.Errorf("UCAN capability denied")
		}
		if proofExp != 0 && requiredExp != 0 && proofExp < requiredExp {
			return "", fmt.Errorf("UCAN proof expired")
		}
		nextProofs := payload.Prf
		if len(nextProofs) == 0 && len(proofs) > 1 {
			nextProofs = proofs[1:]
		}
		return verifyProofChain(payload.Iss, payload.Cap, proofExp, nextProofs)
	}

	var root ucanRootProof
	if err := json.Unmarshal(first, &root); err != nil {
		return "", err
	}
	statement, iss, err := verifyRootProof(root)
	if err != nil {
		return "", err
	}
	if statement.Aud != currentDid {
		return "", fmt.Errorf("root audience mismatch")
	}
	if !capsAllow(statement.Cap, required) {
		return "", fmt.Errorf("root capability denied")
	}
	if requiredExp != 0 && statement.Exp < requiredExp {
		return "", fmt.Errorf("root expired")
	}
	return iss, nil
}

func isUcanToken(token string) bool {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return false
	}
	headerBytes, err := base64UrlDecode(parts[0])
	if err != nil {
		return false
	}
	var header map[string]interface{}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return false
	}
	if typ, ok := header["typ"].(string); ok && typ == "UCAN" {
		return true
	}
	if alg, ok := header["alg"].(string); ok && alg == "EdDSA" {
		return true
	}
	return false
}

func verifyUcanInvocation(token string, expectedAud string, required []ucanCapability) (string, error) {
	payload, exp, err := verifyUcanJws(token)
	if err != nil {
		return "", err
	}
	log.Printf("UCAN invocation token=%s iss=%s aud=%s exp=%d caps=%v proofs=%d", preview(token), payload.Iss, payload.Aud, exp, summarizeCaps(payload.Cap), len(payload.Prf))
	if payload.Aud != expectedAud {
		return "", fmt.Errorf("UCAN audience mismatch expected=%s got=%s", expectedAud, payload.Aud)
	}
	if !capsAllow(payload.Cap, required) {
		return "", fmt.Errorf("UCAN capability denied")
	}
	iss, err := verifyProofChain(payload.Iss, payload.Cap, exp, payload.Prf)
	if err != nil {
		return "", err
	}
	return strings.TrimPrefix(iss, "did:pkh:eth:"), nil
}

func setRefreshCookie(w http.ResponseWriter, token string, maxAgeSeconds int, secure bool, sameSite http.SameSite) {
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    token,
		Path:     "/api/v1/public/auth",
		MaxAge:   maxAgeSeconds,
		HttpOnly: true,
		Secure:   secure,
		SameSite: sameSite,
	})
}

func clearRefreshCookie(w http.ResponseWriter, secure bool, sameSite http.SameSite) {
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    "",
		Path:     "/api/v1/public/auth",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   secure,
		SameSite: sameSite,
	})
}

func signToken(secret string, claims tokenClaims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

func issueTokens(address string, secret string, accessTTL, refreshTTL int64, w http.ResponseWriter, secure bool, sameSite http.SameSite) (string, int64, int64, error) {
	refreshId, err := randomHex(16)
	if err != nil {
		return "", 0, 0, err
	}
	refreshExpiresAt := nowMillis() + refreshTTL

	lock.Lock()
	refreshStore[refreshId] = refreshRecord{Address: address, ExpiresAt: refreshExpiresAt}
	lock.Unlock()

	refreshToken, err := signToken(secret, tokenClaims{
		Address: address,
		Typ:     "refresh",
		Jti:     refreshId,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Duration(refreshTTL) * time.Millisecond)),
		},
	})
	if err != nil {
		return "", 0, 0, err
	}

	setRefreshCookie(w, refreshToken, int(refreshTTL/1000), secure, sameSite)

	accessExpiresAt := nowMillis() + accessTTL
	accessToken, err := signToken(secret, tokenClaims{
		Address: address,
		Typ:     "access",
		Sid:     refreshId,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Duration(accessTTL) * time.Millisecond)),
		},
	})
	if err != nil {
		return "", 0, 0, err
	}

	return accessToken, accessExpiresAt, refreshExpiresAt, nil
}

func getBaseDir() string {
	if base := strings.TrimSpace(os.Getenv("BASE_DIR")); base != "" {
		return base
	}
	_, file, _, ok := runtime.Caller(0)
	if ok {
		return filepath.Dir(file)
	}
	cwd, _ := os.Getwd()
	return cwd
}

func main() {
	port := int(parseIntEnv("PORT", 3201))
	jwtSecret := getenv("JWT_SECRET", "replace-this-in-production")
	accessTTL := parseIntEnv("ACCESS_TTL_MS", 15*60*1000)
	refreshTTL := parseIntEnv("REFRESH_TTL_MS", 7*24*60*60*1000)
	cookieSameSite := strings.ToLower(getenv("COOKIE_SAMESITE", "lax"))
	cookieSecure := parseBoolEnv("COOKIE_SECURE")
	ucanAud := getenv("UCAN_AUD", fmt.Sprintf("did:web:127.0.0.1:%d", port))
	// Recommended: UCAN_RESOURCE=app:<appId> and UCAN_ACTION=read,write; appId = frontend domain or IP:port.
	ucanResource := getenv("UCAN_RESOURCE", "profile")
	ucanAction := getenv("UCAN_ACTION", "read")
	requiredUcanCap := []ucanCapability{{Resource: ucanResource, Action: ucanAction}}

	sameSite := http.SameSiteLaxMode
	switch cookieSameSite {
	case "none":
		sameSite = http.SameSiteNoneMode
	case "strict":
		sameSite = http.SameSiteStrictMode
	}

	allowedOrigins := allowedOriginSet(port)

	mux := http.NewServeMux()

	mux.HandleFunc("/api/v1/public/auth/challenge", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, fail(405, "Method not allowed"))
			return
		}

		var body struct {
			Address string `json:"address"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Address == "" {
			writeJSON(w, http.StatusBadRequest, fail(400, "Missing address"))
			return
		}
		log.Printf("Auth challenge request address=%s", body.Address)

		nonce, err := randomHex(8)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, fail(500, "Failed to generate nonce"))
			return
		}

		issuedAt := nowMillis()
		expiresAt := issuedAt + 5*60*1000
		challenge := fmt.Sprintf("Sign to login\n\nnonce: %s\nissuedAt: %d", nonce, issuedAt)

		lock.Lock()
		challenges[strings.ToLower(body.Address)] = challengeRecord{
			Challenge: challenge,
			IssuedAt:  issuedAt,
			ExpiresAt: expiresAt,
		}
		lock.Unlock()

		writeJSON(w, http.StatusOK, ok(map[string]interface{}{
			"address":   body.Address,
			"challenge": challenge,
			"nonce":     nonce,
			"issuedAt":  issuedAt,
			"expiresAt": expiresAt,
		}))
	})

	mux.HandleFunc("/api/v1/public/auth/verify", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, fail(405, "Method not allowed"))
			return
		}

		var body struct {
			Address   string `json:"address"`
			Signature string `json:"signature"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Address == "" || body.Signature == "" {
			writeJSON(w, http.StatusBadRequest, fail(400, "Missing address or signature"))
			return
		}
		log.Printf("Auth verify request address=%s signature=%s", body.Address, preview(body.Signature))

		key := strings.ToLower(body.Address)

		lock.Lock()
		record, found := challenges[key]
		lock.Unlock()

		if !found {
			writeJSON(w, http.StatusBadRequest, fail(400, "Challenge expired"))
			return
		}

		if nowMillis() > record.ExpiresAt {
			lock.Lock()
			delete(challenges, key)
			lock.Unlock()
			writeJSON(w, http.StatusBadRequest, fail(400, "Challenge expired"))
			return
		}

		recovered, err := recoverAddress(record.Challenge, body.Signature)
		if err != nil || recovered != key {
			writeJSON(w, http.StatusUnauthorized, fail(401, "Invalid signature"))
			return
		}
		log.Printf("Auth verify success address=%s", key)

		lock.Lock()
		delete(challenges, key)
		lock.Unlock()

		accessToken, accessExpiresAt, refreshExpiresAt, err := issueTokens(key, jwtSecret, accessTTL, refreshTTL, w, cookieSecure, sameSite)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, fail(500, "Token issue failed"))
			return
		}

		writeJSON(w, http.StatusOK, ok(map[string]interface{}{
			"address":          key,
			"token":            accessToken,
			"expiresAt":        accessExpiresAt,
			"refreshExpiresAt": refreshExpiresAt,
		}))
	})

	mux.HandleFunc("/api/v1/public/auth/refresh", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, fail(405, "Method not allowed"))
			return
		}

		cookie, err := r.Cookie("refresh_token")
		if err != nil || cookie.Value == "" {
			writeJSON(w, http.StatusUnauthorized, fail(401, "Missing refresh token"))
			return
		}
		log.Printf("Auth refresh request token=%s", preview(cookie.Value))

		parsed, err := jwt.ParseWithClaims(cookie.Value, &tokenClaims{}, func(token *jwt.Token) (interface{}, error) {
			return []byte(jwtSecret), nil
		})
		if err != nil {
			clearRefreshCookie(w, cookieSecure, sameSite)
			writeJSON(w, http.StatusUnauthorized, fail(401, "Invalid refresh token"))
			return
		}

		claims, claimsOk := parsed.Claims.(*tokenClaims)
		if !claimsOk || claims.Typ != "refresh" || claims.Jti == "" {
			clearRefreshCookie(w, cookieSecure, sameSite)
			writeJSON(w, http.StatusUnauthorized, fail(401, "Invalid refresh token"))
			return
		}

		lock.Lock()
		record, exists := refreshStore[claims.Jti]
		if exists && (record.Address != claims.Address || nowMillis() > record.ExpiresAt) {
			delete(refreshStore, claims.Jti)
			exists = false
		}
		if exists {
			delete(refreshStore, claims.Jti)
		}
		lock.Unlock()

		if !exists {
			clearRefreshCookie(w, cookieSecure, sameSite)
			writeJSON(w, http.StatusUnauthorized, fail(401, "Refresh token expired"))
			return
		}
		log.Printf("Auth refresh success address=%s", claims.Address)

		accessToken, accessExpiresAt, refreshExpiresAt, err := issueTokens(claims.Address, jwtSecret, accessTTL, refreshTTL, w, cookieSecure, sameSite)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, fail(500, "Token issue failed"))
			return
		}

		writeJSON(w, http.StatusOK, ok(map[string]interface{}{
			"address":          claims.Address,
			"token":            accessToken,
			"expiresAt":        accessExpiresAt,
			"refreshExpiresAt": refreshExpiresAt,
		}))
	})

	mux.HandleFunc("/api/v1/public/auth/logout", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, fail(405, "Method not allowed"))
			return
		}

		cookie, err := r.Cookie("refresh_token")
		if err == nil && cookie.Value != "" {
			parsed, err := jwt.ParseWithClaims(cookie.Value, &tokenClaims{}, func(token *jwt.Token) (interface{}, error) {
				return []byte(jwtSecret), nil
			})
			if err == nil {
				if claims, ok := parsed.Claims.(*tokenClaims); ok && claims.Jti != "" {
					lock.Lock()
					delete(refreshStore, claims.Jti)
					lock.Unlock()
				}
			}
		}

		clearRefreshCookie(w, cookieSecure, sameSite)
		log.Printf("Auth logout")
		writeJSON(w, http.StatusOK, ok(map[string]interface{}{"logout": true}))
	})

	mux.HandleFunc("/api/v1/public/profile", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, fail(405, "Method not allowed"))
			return
		}

		authHeader := r.Header.Get("Authorization")
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			writeJSON(w, http.StatusUnauthorized, fail(401, "Missing access token"))
			return
		}
		token := parts[1]
		if isUcanToken(token) {
			address, err := verifyUcanInvocation(token, ucanAud, requiredUcanCap)
			if err != nil {
				log.Printf("UCAN profile failed error=%s", err.Error())
				writeJSON(w, http.StatusUnauthorized, fail(401, err.Error()))
				return
			}
			log.Printf("UCAN profile ok address=%s", address)
			writeJSON(w, http.StatusOK, ok(map[string]interface{}{
				"address":  address,
				"issuedAt": nowMillis(),
			}))
			return
		}

		parsed, err := jwt.ParseWithClaims(token, &tokenClaims{}, func(token *jwt.Token) (interface{}, error) {
			return []byte(jwtSecret), nil
		})
		if err != nil {
			log.Printf("JWT profile failed error=%s", err.Error())
			writeJSON(w, http.StatusUnauthorized, fail(401, "Invalid or expired access token"))
			return
		}

		claims, claimsOk := parsed.Claims.(*tokenClaims)
		if !claimsOk || claims.Typ != "access" {
			writeJSON(w, http.StatusUnauthorized, fail(401, "Invalid access token"))
			return
		}
		log.Printf("JWT profile ok address=%s", claims.Address)

		writeJSON(w, http.StatusOK, ok(map[string]interface{}{
			"address":  claims.Address,
			"issuedAt": nowMillis(),
		}))
	})

	baseDir := getBaseDir()
	frontendDir := filepath.Join(baseDir, "..", "..", "frontend")
	distDir := filepath.Join(baseDir, "..", "..", "..", "dist")

	mux.Handle("/dist/", http.StripPrefix("/dist/", http.FileServer(http.Dir(distDir))))
	mux.Handle("/", http.FileServer(http.Dir(frontendDir)))

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recorder := &statusRecorder{ResponseWriter: w}
		start := time.Now()

		origin := r.Header.Get("Origin")
		if origin != "" {
			if _, ok := allowedOrigins[origin]; ok {
				recorder.Header().Set("Access-Control-Allow-Origin", origin)
				recorder.Header().Set("Vary", "Origin")
				recorder.Header().Set("Access-Control-Allow-Credentials", "true")
				recorder.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
				recorder.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			}
		}

		if r.Method == http.MethodOptions {
			recorder.WriteHeader(http.StatusNoContent)
			log.Printf("HTTP method=%s path=%s status=%d durationMs=%d origin=%s", r.Method, r.URL.Path, recorder.status, time.Since(start).Milliseconds(), origin)
			return
		}

		mux.ServeHTTP(recorder, r)
		status := recorder.status
		if status == 0 {
			status = http.StatusOK
		}
		log.Printf("HTTP method=%s path=%s status=%d durationMs=%d origin=%s", r.Method, r.URL.Path, status, time.Since(start).Milliseconds(), origin)
	})

	addr := fmt.Sprintf(":%d", port)
	log.Printf("Auth server running at http://127.0.0.1:%d", port)
	if err := http.ListenAndServe(addr, handler); err != nil {
		log.Fatal(err)
	}
}
