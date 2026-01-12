package main

import (
  "crypto/rand"
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

var (
  challenges   = make(map[string]challengeRecord)
  refreshStore = make(map[string]refreshRecord)
  lock         sync.Mutex
)

func nowMillis() int64 {
  return time.Now().UnixMilli()
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
    fmt.Sprintf("http://localhost:%d", port),
    fmt.Sprintf("http://127.0.0.1:%d", port),
    "http://localhost:8000",
    "http://127.0.0.1:8000",
    "http://localhost:8001",
    "http://127.0.0.1:8001",
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
  port := int(parseIntEnv("PORT", 4001))
  jwtSecret := getenv("JWT_SECRET", "replace-this-in-production")
  accessTTL := parseIntEnv("ACCESS_TTL_MS", 15*60*1000)
  refreshTTL := parseIntEnv("REFRESH_TTL_MS", 7*24*60*60*1000)
  cookieSameSite := strings.ToLower(getenv("COOKIE_SAMESITE", "lax"))
  cookieSecure := parseBoolEnv("COOKIE_SECURE")

  sameSite := http.SameSiteLaxMode
  if cookieSameSite == "none" {
    sameSite = http.SameSiteNoneMode
  } else if cookieSameSite == "strict" {
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
      "address":  body.Address,
      "challenge": challenge,
      "nonce":    nonce,
      "issuedAt": issuedAt,
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
    writeJSON(w, http.StatusOK, ok(map[string]interface{}{"logout": true}))
  })

  mux.HandleFunc("/api/v1/private/profile", func(w http.ResponseWriter, r *http.Request) {
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

    parsed, err := jwt.ParseWithClaims(parts[1], &tokenClaims{}, func(token *jwt.Token) (interface{}, error) {
      return []byte(jwtSecret), nil
    })
    if err != nil {
      writeJSON(w, http.StatusUnauthorized, fail(401, "Invalid or expired access token"))
      return
    }

    claims, claimsOk := parsed.Claims.(*tokenClaims)
    if !claimsOk || claims.Typ != "access" {
      writeJSON(w, http.StatusUnauthorized, fail(401, "Invalid access token"))
      return
    }

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
    origin := r.Header.Get("Origin")
    if origin != "" {
      if _, ok := allowedOrigins[origin]; ok {
        w.Header().Set("Access-Control-Allow-Origin", origin)
        w.Header().Set("Vary", "Origin")
        w.Header().Set("Access-Control-Allow-Credentials", "true")
        w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
        w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
      }
    }

    if r.Method == http.MethodOptions {
      w.WriteHeader(http.StatusNoContent)
      return
    }

    mux.ServeHTTP(w, r)
  })

  addr := fmt.Sprintf(":%d", port)
  log.Printf("Auth server running at http://localhost:%d", port)
  if err := http.ListenAndServe(addr, handler); err != nil {
    log.Fatal(err)
  }
}
