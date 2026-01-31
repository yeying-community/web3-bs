package com.yeying.demo;

import static spark.Spark.*;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.web3j.crypto.Keys;
import org.web3j.crypto.Sign;
import org.web3j.utils.Numeric;

public class AuthServer {
  private static final Gson GSON = new Gson();
  private static final Map<String, ChallengeRecord> CHALLENGES = new ConcurrentHashMap<>();
  private static final Map<String, RefreshRecord> REFRESH_STORE = new ConcurrentHashMap<>();

  private static final String JWT_SECRET = getEnv("JWT_SECRET", "replace-this-in-production");
  private static final long ACCESS_TTL_MS = getEnvLong("ACCESS_TTL_MS", 15 * 60 * 1000L);
  private static final long REFRESH_TTL_MS = getEnvLong("REFRESH_TTL_MS", 7 * 24 * 60 * 60 * 1000L);
  private static final String COOKIE_SAMESITE = getEnv("COOKIE_SAMESITE", "lax").toLowerCase();
  private static final boolean COOKIE_SECURE = getEnv("COOKIE_SECURE", "").matches("(?i)^(1|true|yes)$");

  private static final Algorithm JWT_ALG = Algorithm.HMAC256(JWT_SECRET);
  private static final JWTVerifier JWT_VERIFIER = JWT.require(JWT_ALG).build();

  private static final int PORT = (int) getEnvLong("PORT", 3202);
  private static final String UCAN_AUD = getEnv("UCAN_AUD", "did:web:127.0.0.1:" + PORT);
  private static final String UCAN_RESOURCE = getEnv("UCAN_RESOURCE", "profile");
  private static final String UCAN_ACTION = getEnv("UCAN_ACTION", "read");
  private static final UcanCapability REQUIRED_UCAN_CAP = new UcanCapability(UCAN_RESOURCE, UCAN_ACTION);
  private static final String BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

  private static final Set<String> ALLOWED_ORIGINS = allowedOrigins(PORT);

  public static void main(String[] args) {
    port(PORT);

    before((req, res) -> {
      String origin = req.headers("Origin");
      if (origin != null && ALLOWED_ORIGINS.contains(origin)) {
        res.header("Access-Control-Allow-Origin", origin);
        res.header("Vary", "Origin");
        res.header("Access-Control-Allow-Credentials", "true");
        res.header("Access-Control-Allow-Headers", "Content-Type, Authorization");
        res.header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
      }
    });

    before((req, res) -> {
      String origin = req.headers("Origin");
      logInfo("HTTP request method=%s path=%s origin=%s", req.requestMethod(), req.pathInfo(), origin == null ? "" : origin);
    });

    afterAfter((req, res) -> {
      logInfo("HTTP response method=%s path=%s status=%d", req.requestMethod(), req.pathInfo(), res.status());
    });

    options("/*", (req, res) -> {
      res.status(204);
      return "";
    });

    post("/api/v1/public/auth/challenge", (req, res) -> {
      JsonObject body = parseJson(req.body());
      String address = getString(body, "address");
      if (address == null) {
        res.status(400);
        return jsonResponse(res, fail(400, "Missing address"));
      }
      logInfo("Auth challenge request address=%s", address);

      String nonce = randomHex(8);
      long issuedAt = nowMillis();
      long expiresAt = issuedAt + 5 * 60 * 1000L;
      String challenge = "Sign to login\n\nnonce: " + nonce + "\nissuedAt: " + issuedAt;

      CHALLENGES.put(address.toLowerCase(), new ChallengeRecord(challenge, issuedAt, expiresAt));

      Map<String, Object> data = new HashMap<>();
      data.put("address", address);
      data.put("challenge", challenge);
      data.put("nonce", nonce);
      data.put("issuedAt", issuedAt);
      data.put("expiresAt", expiresAt);

      return jsonResponse(res, ok(data));
    });

    post("/api/v1/public/auth/verify", (req, res) -> {
      JsonObject body = parseJson(req.body());
      String address = getString(body, "address");
      String signature = getString(body, "signature");
      if (address == null || signature == null) {
        res.status(400);
        return jsonResponse(res, fail(400, "Missing address or signature"));
      }
      logInfo("Auth verify request address=%s signature=%s", address, preview(signature));

      String key = address.toLowerCase();
      ChallengeRecord record = CHALLENGES.get(key);
      if (record == null) {
        res.status(400);
        return jsonResponse(res, fail(400, "Challenge expired"));
      }

      if (nowMillis() > record.expiresAt) {
        CHALLENGES.remove(key);
        res.status(400);
        return jsonResponse(res, fail(400, "Challenge expired"));
      }

      String recovered;
      try {
        recovered = recoverAddress(record.challenge, signature);
      } catch (Exception e) {
        res.status(401);
        return jsonResponse(res, fail(401, "Invalid signature"));
      }

      if (!recovered.equals(key)) {
        res.status(401);
        return jsonResponse(res, fail(401, "Invalid signature"));
      }
      logInfo("Auth verify success address=%s", key);

      CHALLENGES.remove(key);

      TokenBundle tokens = issueTokens(key, res);

      Map<String, Object> data = new HashMap<>();
      data.put("address", key);
      data.put("token", tokens.accessToken);
      data.put("expiresAt", tokens.accessExpiresAt);
      data.put("refreshExpiresAt", tokens.refreshExpiresAt);

      return jsonResponse(res, ok(data));
    });

    post("/api/v1/public/auth/refresh", (req, res) -> {
      String refreshToken = req.cookie("refresh_token");
      if (refreshToken == null || refreshToken.isEmpty()) {
        res.status(401);
        return jsonResponse(res, fail(401, "Missing refresh token"));
      }
      logInfo("Auth refresh request token=%s", preview(refreshToken));

      DecodedJWT decoded;
      try {
        decoded = JWT_VERIFIER.verify(refreshToken);
      } catch (JWTVerificationException e) {
        clearRefreshCookie(res);
        res.status(401);
        return jsonResponse(res, fail(401, "Invalid refresh token"));
      }

      if (!"refresh".equals(decoded.getClaim("typ").asString()) || decoded.getClaim("jti").isMissing()) {
        clearRefreshCookie(res);
        res.status(401);
        return jsonResponse(res, fail(401, "Invalid refresh token"));
      }

      String jti = decoded.getClaim("jti").asString();
      RefreshRecord record = REFRESH_STORE.get(jti);
      if (record == null || !record.address.equals(decoded.getClaim("address").asString()) || nowMillis() > record.expiresAt) {
        REFRESH_STORE.remove(jti);
        clearRefreshCookie(res);
        res.status(401);
        return jsonResponse(res, fail(401, "Refresh token expired"));
      }
      logInfo("Auth refresh success address=%s", decoded.getClaim("address").asString());

      REFRESH_STORE.remove(jti);

      TokenBundle tokens = issueTokens(decoded.getClaim("address").asString(), res);

      Map<String, Object> data = new HashMap<>();
      data.put("address", decoded.getClaim("address").asString());
      data.put("token", tokens.accessToken);
      data.put("expiresAt", tokens.accessExpiresAt);
      data.put("refreshExpiresAt", tokens.refreshExpiresAt);

      return jsonResponse(res, ok(data));
    });

    post("/api/v1/public/auth/logout", (req, res) -> {
      String refreshToken = req.cookie("refresh_token");
      if (refreshToken != null && !refreshToken.isEmpty()) {
        try {
          DecodedJWT decoded = JWT_VERIFIER.verify(refreshToken);
          String jti = decoded.getClaim("jti").asString();
          if (jti != null) {
            REFRESH_STORE.remove(jti);
          }
        } catch (JWTVerificationException e) {
          // ignore
        }
      }

      clearRefreshCookie(res);
      Map<String, Object> data = new HashMap<>();
      data.put("logout", true);
      logInfo("Auth logout");
      return jsonResponse(res, ok(data));
    });

    get("/api/v1/public/profile", (req, res) -> {
      String auth = req.headers("Authorization");
      if (auth == null || !auth.toLowerCase().startsWith("bearer ")) {
        res.status(401);
        return jsonResponse(res, fail(401, "Missing access token"));
      }

      String token = auth.substring(7).trim();
      if (isUcanToken(token)) {
        try {
          String address = verifyUcanInvocation(token);
          Map<String, Object> data = new HashMap<>();
          data.put("address", address);
          data.put("issuedAt", nowMillis());
          logInfo("UCAN profile ok address=%s", address);
          return jsonResponse(res, ok(data));
        } catch (Exception e) {
          res.status(401);
          logWarn("UCAN profile failed error=%s", e.getMessage());
          return jsonResponse(res, fail(401, e.getMessage()));
        }
      }

      DecodedJWT decoded;
      try {
        decoded = JWT_VERIFIER.verify(token);
      } catch (JWTVerificationException e) {
        res.status(401);
        return jsonResponse(res, fail(401, "Invalid or expired access token"));
      }

      if (!"access".equals(decoded.getClaim("typ").asString())) {
        res.status(401);
        return jsonResponse(res, fail(401, "Invalid access token"));
      }

      Map<String, Object> data = new HashMap<>();
      data.put("address", decoded.getClaim("address").asString());
      data.put("issuedAt", nowMillis());
      logInfo("JWT profile ok address=%s", decoded.getClaim("address").asString());
      return jsonResponse(res, ok(data));
    });

    Path baseDir = resolveBaseDir();
    Path frontendDir = baseDir.resolve("../../frontend").normalize();
    Path distDir = baseDir.resolve("../../../dist").normalize();

    get("/", (req, res) -> serveFile(res, frontendDir.resolve("dapp.html")));
    get("/dapp.html", (req, res) -> serveFile(res, frontendDir.resolve("dapp.html")));
    get("/dist/*", (req, res) -> {
      String[] splat = req.splat();
      if (splat.length == 0) {
        res.status(404);
        return "Not Found";
      }
      return serveFile(res, distDir.resolve(splat[0]));
    });

    System.out.println("Auth server running at http://127.0.0.1:" + PORT);
  }

  private static Path resolveBaseDir() {
    String base = System.getenv("BASE_DIR");
    if (base != null && !base.isBlank()) {
      return Paths.get(base).toAbsolutePath();
    }
    return Paths.get(System.getProperty("user.dir")).toAbsolutePath();
  }

  private static Object serveFile(spark.Response res, Path path) throws IOException {
    if (!Files.exists(path)) {
      res.status(404);
      return "Not Found";
    }
    String contentType = Files.probeContentType(path);
    if (contentType == null) {
      contentType = guessContentType(path);
    }
    res.type(contentType);
    return Files.readAllBytes(path);
  }

  private static String guessContentType(Path path) {
    String name = path.getFileName().toString().toLowerCase();
    if (name.endsWith(".js")) return "application/javascript";
    if (name.endsWith(".css")) return "text/css";
    if (name.endsWith(".html")) return "text/html";
    return "application/octet-stream";
  }

  private static String jsonResponse(spark.Response res, Object payload) {
    res.type("application/json");
    return GSON.toJson(payload);
  }

  private static JsonObject parseJson(String body) {
    if (body == null || body.isBlank()) {
      return new JsonObject();
    }
    try {
      return GSON.fromJson(body, JsonObject.class);
    } catch (Exception e) {
      return new JsonObject();
    }
  }

  private static String getString(JsonObject body, String key) {
    if (body == null) return null;
    JsonElement element = body.get(key);
    if (element == null || element.isJsonNull()) return null;
    return element.getAsString();
  }

  private static long nowMillis() {
    return Instant.now().toEpochMilli();
  }

  private static String preview(String value) {
    if (value == null || value.isBlank()) return "";
    if (value.length() <= 20) return value;
    return value.substring(0, 8) + "..." + value.substring(value.length() - 8);
  }

  private static void logInfo(String message, Object... args) {
    log("INFO", message, args);
  }

  private static void logWarn(String message, Object... args) {
    log("WARN", message, args);
  }

  private static void logError(String message, Object... args) {
    log("ERROR", message, args);
  }

  private static void log(String level, String message, Object... args) {
    String text = args == null || args.length == 0 ? message : String.format(message, args);
    String line = Instant.now() + " " + level + " " + text;
    if ("ERROR".equals(level)) {
      System.err.println(line);
      return;
    }
    System.out.println(line);
  }

  private static Map<String, Object> ok(Object data) {
    Map<String, Object> payload = new HashMap<>();
    payload.put("code", 0);
    payload.put("message", "ok");
    payload.put("data", data);
    payload.put("timestamp", nowMillis());
    return payload;
  }

  private static Map<String, Object> fail(int code, String message) {
    Map<String, Object> payload = new HashMap<>();
    payload.put("code", code);
    payload.put("message", message);
    payload.put("data", null);
    payload.put("timestamp", nowMillis());
    return payload;
  }

  private static String recoverAddress(String message, String signature) throws Exception {
    byte[] sigBytes = Numeric.hexStringToByteArray(signature);
    if (sigBytes.length != 65) {
      throw new IllegalArgumentException("Invalid signature length");
    }
    byte v = sigBytes[64];
    if (v < 27) {
      v += 27;
    }
    byte[] r = new byte[32];
    byte[] s = new byte[32];
    System.arraycopy(sigBytes, 0, r, 0, 32);
    System.arraycopy(sigBytes, 32, s, 0, 32);

    Sign.SignatureData sigData = new Sign.SignatureData(v, r, s);
    byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
    String address = "0x" + Keys.getAddress(Sign.signedPrefixedMessageToKey(messageBytes, sigData));
    return address.toLowerCase();
  }

  private static TokenBundle issueTokens(String address, spark.Response res) {
    String refreshId = UUID.randomUUID().toString().replace("-", "");
    long refreshExpiresAt = nowMillis() + REFRESH_TTL_MS;
    REFRESH_STORE.put(refreshId, new RefreshRecord(address, refreshExpiresAt));

    String refreshToken = JWT.create()
        .withClaim("address", address)
        .withClaim("typ", "refresh")
        .withClaim("jti", refreshId)
        .withExpiresAt(new Date(System.currentTimeMillis() + REFRESH_TTL_MS))
        .sign(JWT_ALG);

    setRefreshCookie(res, refreshToken, (int) (REFRESH_TTL_MS / 1000));

    String accessToken = JWT.create()
        .withClaim("address", address)
        .withClaim("typ", "access")
        .withClaim("sid", refreshId)
        .withExpiresAt(new Date(System.currentTimeMillis() + ACCESS_TTL_MS))
        .sign(JWT_ALG);

    return new TokenBundle(accessToken, nowMillis() + ACCESS_TTL_MS, refreshExpiresAt);
  }

  private static void setRefreshCookie(spark.Response res, String token, int maxAge) {
    StringBuilder cookie = new StringBuilder();
    cookie.append("refresh_token=").append(token).append("; ");
    cookie.append("Max-Age=").append(maxAge).append("; ");
    cookie.append("Path=/api/v1/public/auth; ");
    cookie.append("HttpOnly; ");
    cookie.append("SameSite=").append(COOKIE_SAMESITE.substring(0, 1).toUpperCase()).append(COOKIE_SAMESITE.substring(1)).append("; ");
    if (COOKIE_SECURE) {
      cookie.append("Secure; ");
    }
    res.header("Set-Cookie", cookie.toString());
  }

  private static void clearRefreshCookie(spark.Response res) {
    StringBuilder cookie = new StringBuilder();
    cookie.append("refresh_token=; ");
    cookie.append("Max-Age=0; ");
    cookie.append("Path=/api/v1/public/auth; ");
    cookie.append("HttpOnly; ");
    cookie.append("SameSite=").append(COOKIE_SAMESITE.substring(0, 1).toUpperCase()).append(COOKIE_SAMESITE.substring(1)).append("; ");
    if (COOKIE_SECURE) {
      cookie.append("Secure; ");
    }
    res.header("Set-Cookie", cookie.toString());
  }

  private static byte[] base64UrlDecode(String value) {
    return Base64.getUrlDecoder().decode(value);
  }

  private static byte[] base58Decode(String value) {
    List<Integer> bytes = new ArrayList<>();
    bytes.add(0);
    for (int i = 0; i < value.length(); i++) {
      int index = BASE58_ALPHABET.indexOf(value.charAt(i));
      if (index < 0) {
        throw new IllegalArgumentException("Invalid base58 character");
      }
      int carry = index;
      for (int j = 0; j < bytes.size(); j++) {
        carry += bytes.get(j) * 58;
        bytes.set(j, carry & 0xff);
        carry >>= 8;
      }
      while (carry > 0) {
        bytes.add(carry & 0xff);
        carry >>= 8;
      }
    }
    int zeros = 0;
    while (zeros < value.length() && value.charAt(zeros) == '1') {
      zeros++;
    }
    byte[] output = new byte[zeros + bytes.size()];
    for (int i = 0; i < zeros; i++) {
      output[i] = 0;
    }
    for (int i = 0; i < bytes.size(); i++) {
      output[output.length - 1 - i] = bytes.get(i).byteValue();
    }
    return output;
  }

  private static byte[] didKeyToPublicKey(String did) {
    if (did == null || !did.startsWith("did:key:z")) {
      throw new IllegalArgumentException("Invalid did:key format");
    }
    byte[] decoded = base58Decode(did.substring("did:key:z".length()));
    if (decoded.length < 3 || (decoded[0] & 0xff) != 0xed || (decoded[1] & 0xff) != 0x01) {
      throw new IllegalArgumentException("Unsupported did:key type");
    }
    byte[] raw = new byte[decoded.length - 2];
    System.arraycopy(decoded, 2, raw, 0, raw.length);
    return raw;
  }

  private static long normalizeEpochMillis(Long value) {
    if (value == null || value == 0) {
      return 0;
    }
    if (value < 1_000_000_000_000L) {
      return value * 1000L;
    }
    return value;
  }

  private static boolean matchPattern(String pattern, String value) {
    if ("*".equals(pattern)) return true;
    if (pattern != null && pattern.endsWith("*")) {
      return value != null && value.startsWith(pattern.substring(0, pattern.length() - 1));
    }
    return pattern != null && pattern.equals(value);
  }

  private static List<UcanCapability> parseCapabilities(JsonElement element) {
    List<UcanCapability> list = new ArrayList<>();
    if (element == null || !element.isJsonArray()) {
      return list;
    }
    for (JsonElement capEl : element.getAsJsonArray()) {
      if (!capEl.isJsonObject()) continue;
      JsonObject obj = capEl.getAsJsonObject();
      String resource = getString(obj, "resource");
      String action = getString(obj, "action");
      if (resource != null && action != null) {
        list.add(new UcanCapability(resource, action));
      }
    }
    return list;
  }

  private static boolean capsAllow(List<UcanCapability> available, List<UcanCapability> required) {
    if (available == null || available.isEmpty()) return false;
    for (UcanCapability req : required) {
      boolean matched = false;
      for (UcanCapability cap : available) {
        if (matchPattern(cap.resource, req.resource) && matchPattern(cap.action, req.action)) {
          matched = true;
          break;
        }
      }
      if (!matched) return false;
    }
    return true;
  }

  private static UcanStatement extractUcanStatement(String message) {
    if (message == null) return null;
    String[] lines = message.split("\\r?\\n");
    for (String line : lines) {
      String trimmed = line.trim();
      if (trimmed.toUpperCase().startsWith("UCAN-AUTH")) {
        String payload = trimmed.substring("UCAN-AUTH".length()).replaceFirst("^\\s*:?\\s*", "");
        JsonObject json = GSON.fromJson(payload, JsonObject.class);
        if (json == null) return null;
        String aud = getString(json, "aud");
        List<UcanCapability> cap = parseCapabilities(json.get("cap"));
        Long exp = getLong(json, "exp");
        Long nbf = getLong(json, "nbf");
        if (aud == null || cap.isEmpty() || exp == null) return null;
        return new UcanStatement(aud, cap, normalizeEpochMillis(exp), normalizeEpochMillis(nbf));
      }
    }
    return null;
  }

  private static UcanRootResult verifyRootProof(JsonObject root) {
    if (root == null || !"siwe".equals(getString(root, "type"))) {
      throw new IllegalArgumentException("Invalid root proof");
    }
    JsonObject siwe = root.has("siwe") && root.get("siwe").isJsonObject() ? root.getAsJsonObject("siwe") : null;
    String message = siwe == null ? null : getString(siwe, "message");
    String signature = siwe == null ? null : getString(siwe, "signature");
    if (message == null || signature == null) {
      throw new IllegalArgumentException("Missing SIWE message");
    }

    String recovered;
    try {
      recovered = recoverAddress(message, signature);
    } catch (Exception e) {
      throw new IllegalArgumentException("Invalid SIWE signature");
    }
    String iss = "did:pkh:eth:" + recovered;
    String rootIss = getString(root, "iss");
    if (rootIss != null && !rootIss.equals(iss)) {
      logWarn("UCAN root issuer mismatch rootIss=%s recoveredIss=%s", rootIss, iss);
      throw new IllegalArgumentException("Root issuer mismatch");
    }

    UcanStatement statement = extractUcanStatement(message);
    if (statement == null) {
      throw new IllegalArgumentException("Missing UCAN statement");
    }

    String rootAud = getString(root, "aud");
    if (rootAud != null && !rootAud.equals(statement.aud)) {
      logWarn("UCAN root audience mismatch rootAud=%s aud=%s", rootAud, statement.aud);
      throw new IllegalArgumentException("Root audience mismatch");
    }
    Long rootExp = getLong(root, "exp");
    if (rootExp != null && normalizeEpochMillis(rootExp) != statement.exp) {
      logWarn("UCAN root expiry mismatch rootExp=%s exp=%s", rootExp, statement.exp);
      throw new IllegalArgumentException("Root expiry mismatch");
    }

    long now = nowMillis();
    if (statement.nbf != null && now < statement.nbf) {
      throw new IllegalArgumentException("Root not active");
    }
    if (now > statement.exp) {
      throw new IllegalArgumentException("Root expired");
    }

    logInfo("UCAN root verified iss=%s aud=%s exp=%s nbf=%s caps=%s", iss, statement.aud, statement.exp, statement.nbf, statement.cap);
    return new UcanRootResult(iss, statement);
  }

  private static DecodedUcan decodeUcanToken(String token) {
    String[] parts = token.split("\\.");
    if (parts.length != 3) {
      throw new IllegalArgumentException("Invalid UCAN token");
    }
    JsonObject header = GSON.fromJson(new String(base64UrlDecode(parts[0]), StandardCharsets.UTF_8), JsonObject.class);
    JsonObject payload = GSON.fromJson(new String(base64UrlDecode(parts[1]), StandardCharsets.UTF_8), JsonObject.class);
    byte[] signature = base64UrlDecode(parts[2]);
    return new DecodedUcan(header, payload, signature, parts[0] + "." + parts[1]);
  }

  private static VerifiedUcan verifyUcanJws(String token) {
    DecodedUcan decoded = decodeUcanToken(token);
    String alg = getString(decoded.header, "alg");
    if (alg != null && !"EdDSA".equals(alg)) {
      throw new IllegalArgumentException("Unsupported UCAN alg");
    }
    String iss = getString(decoded.payload, "iss");
    byte[] rawKey = didKeyToPublicKey(iss);
    Ed25519Signer signer = new Ed25519Signer();
    signer.init(false, new Ed25519PublicKeyParameters(rawKey, 0));
    byte[] signingBytes = decoded.signingInput.getBytes(StandardCharsets.UTF_8);
    signer.update(signingBytes, 0, signingBytes.length);
    if (!signer.verifySignature(decoded.signature)) {
      throw new IllegalArgumentException("Invalid UCAN signature");
    }

    long exp = normalizeEpochMillis(getLong(decoded.payload, "exp"));
    Long nbfValue = getLong(decoded.payload, "nbf");
    long nbf = normalizeEpochMillis(nbfValue);
    long now = nowMillis();
    if (nbf != 0 && now < nbf) {
      throw new IllegalArgumentException("UCAN not active");
    }
    if (exp != 0 && now > exp) {
      throw new IllegalArgumentException("UCAN expired");
    }

    logInfo("UCAN JWS verified iss=%s aud=%s exp=%s nbf=%s caps=%s", getString(decoded.payload, "iss"), getString(decoded.payload, "aud"), exp, nbf, parseCapabilities(decoded.payload.get("cap")));
    return new VerifiedUcan(decoded.payload, exp);
  }

  private static String verifyProofChain(String currentDid, List<UcanCapability> requiredCap, long requiredExp, JsonArray proofs) {
    if (proofs == null || proofs.size() == 0) {
      throw new IllegalArgumentException("Missing UCAN proof chain");
    }
    logInfo("UCAN proof chain currentDid=%s requiredExp=%s proofs=%s requiredCaps=%s", currentDid, requiredExp, proofs.size(), requiredCap);
    JsonElement first = proofs.get(0);
    if (first.isJsonPrimitive() && first.getAsJsonPrimitive().isString()) {
      VerifiedUcan verified = verifyUcanJws(first.getAsString());
      JsonObject payload = verified.payload;
      String aud = getString(payload, "aud");
      if (!currentDid.equals(aud)) {
        throw new IllegalArgumentException(String.format("UCAN audience mismatch expected=%s got=%s", currentDid, aud));
      }
      List<UcanCapability> cap = parseCapabilities(payload.get("cap"));
      if (!capsAllow(cap, requiredCap)) {
        throw new IllegalArgumentException("UCAN capability denied");
      }
      if (verified.exp != 0 && requiredExp != 0 && verified.exp < requiredExp) {
        throw new IllegalArgumentException("UCAN proof expired");
      }
      JsonArray nextProofs = payload.has("prf") && payload.get("prf").isJsonArray()
          ? payload.getAsJsonArray("prf")
          : null;
      if ((nextProofs == null || nextProofs.size() == 0) && proofs.size() > 1) {
        JsonArray rest = new JsonArray();
        for (int i = 1; i < proofs.size(); i++) {
          rest.add(proofs.get(i));
        }
        nextProofs = rest;
      }
      return verifyProofChain(getString(payload, "iss"), cap, verified.exp, nextProofs);
    }

    if (!first.isJsonObject()) {
      throw new IllegalArgumentException("Invalid UCAN proof");
    }
    UcanRootResult root = verifyRootProof(first.getAsJsonObject());
    if (!currentDid.equals(root.statement.aud)) {
      throw new IllegalArgumentException("Root audience mismatch");
    }
    if (!capsAllow(root.statement.cap, requiredCap)) {
      throw new IllegalArgumentException("Root capability denied");
    }
    if (requiredExp != 0 && root.statement.exp < requiredExp) {
      throw new IllegalArgumentException("Root expired");
    }
    return root.iss;
  }

  private static boolean isUcanToken(String token) {
    try {
      String[] parts = token.split("\\.");
      if (parts.length < 2) return false;
      JsonObject header = GSON.fromJson(new String(base64UrlDecode(parts[0]), StandardCharsets.UTF_8), JsonObject.class);
      String typ = getString(header, "typ");
      String alg = getString(header, "alg");
      return "UCAN".equals(typ) || "EdDSA".equals(alg);
    } catch (Exception e) {
      return false;
    }
  }

  private static String verifyUcanInvocation(String token) {
    VerifiedUcan verified = verifyUcanJws(token);
    JsonObject payload = verified.payload;
    logInfo(
        "UCAN invocation token=%s iss=%s aud=%s exp=%s caps=%s proofs=%s",
        preview(token),
        getString(payload, "iss"),
        getString(payload, "aud"),
        verified.exp,
        parseCapabilities(payload.get("cap")),
        payload.has("prf") && payload.get("prf").isJsonArray() ? payload.getAsJsonArray("prf").size() : 0
    );
    String aud = getString(payload, "aud");
    if (!UCAN_AUD.equals(aud)) {
      throw new IllegalArgumentException(String.format("UCAN audience mismatch expected=%s got=%s", UCAN_AUD, aud));
    }
    List<UcanCapability> cap = parseCapabilities(payload.get("cap"));
    List<UcanCapability> required = new ArrayList<>();
    required.add(REQUIRED_UCAN_CAP);
    if (!capsAllow(cap, required)) {
      throw new IllegalArgumentException("UCAN capability denied");
    }
    JsonArray proofs = payload.has("prf") && payload.get("prf").isJsonArray() ? payload.getAsJsonArray("prf") : new JsonArray();
    String iss = verifyProofChain(getString(payload, "iss"), cap, verified.exp, proofs);
    return iss.replace("did:pkh:eth:", "");
  }

  private static Long getLong(JsonObject body, String key) {
    if (body == null) return null;
    JsonElement element = body.get(key);
    if (element == null || element.isJsonNull()) return null;
    try {
      return element.getAsLong();
    } catch (Exception e) {
      return null;
    }
  }

  private static String randomHex(int bytes) {
    SecureRandom random = new SecureRandom();
    byte[] buffer = new byte[bytes];
    random.nextBytes(buffer);
    return Numeric.toHexStringNoPrefix(buffer);
  }

  private static Set<String> allowedOrigins(int port) {
    String[] defaults = new String[] {
        "http://127.0.0.1:" + port,
        "http://127.0.0.1:" + port,
        "http://127.0.0.1:8000",
        "http://127.0.0.1:8000",
        "http://127.0.0.1:8001",
        "http://127.0.0.1:8001",
        "http://127.0.0.1:3201",
        "http://127.0.0.1:3201",
        "http://127.0.0.1:3202",
        "http://127.0.0.1:3202",
        "http://127.0.0.1:3203",
        "http://127.0.0.1:3203",
        "http://127.0.0.1:3204",
        "http://127.0.0.1:3204",
    };
    String env = getEnv("CORS_ORIGINS", String.join(",", defaults));
    Set<String> set = new HashSet<>();
    for (String origin : env.split(",")) {
      String trimmed = origin.trim();
      if (!trimmed.isEmpty()) {
        set.add(trimmed);
      }
    }
    return set;
  }

  private static String getEnv(String key, String fallback) {
    String value = System.getenv(key);
    if (value == null || value.isBlank()) {
      return fallback;
    }
    return value.trim();
  }

  private static long getEnvLong(String key, long fallback) {
    String value = System.getenv(key);
    if (value == null || value.isBlank()) {
      return fallback;
    }
    try {
      return Long.parseLong(value.trim());
    } catch (NumberFormatException e) {
      return fallback;
    }
  }

  private static class UcanCapability {
    final String resource;
    final String action;

    UcanCapability(String resource, String action) {
      this.resource = resource;
      this.action = action;
    }
  }

  private static class UcanStatement {
    final String aud;
    final List<UcanCapability> cap;
    final long exp;
    final Long nbf;

    UcanStatement(String aud, List<UcanCapability> cap, long exp, Long nbf) {
      this.aud = aud;
      this.cap = cap;
      this.exp = exp;
      this.nbf = nbf;
    }
  }

  private static class UcanRootResult {
    final String iss;
    final UcanStatement statement;

    UcanRootResult(String iss, UcanStatement statement) {
      this.iss = iss;
      this.statement = statement;
    }
  }

  private static class DecodedUcan {
    final JsonObject header;
    final JsonObject payload;
    final byte[] signature;
    final String signingInput;

    DecodedUcan(JsonObject header, JsonObject payload, byte[] signature, String signingInput) {
      this.header = header;
      this.payload = payload;
      this.signature = signature;
      this.signingInput = signingInput;
    }
  }

  private static class VerifiedUcan {
    final JsonObject payload;
    final long exp;

    VerifiedUcan(JsonObject payload, long exp) {
      this.payload = payload;
      this.exp = exp;
    }
  }

  private static class ChallengeRecord {
    final String challenge;
    final long issuedAt;
    final long expiresAt;

    ChallengeRecord(String challenge, long issuedAt, long expiresAt) {
      this.challenge = challenge;
      this.issuedAt = issuedAt;
      this.expiresAt = expiresAt;
    }
  }

  private static class RefreshRecord {
    final String address;
    final long expiresAt;

    RefreshRecord(String address, long expiresAt) {
      this.address = address;
      this.expiresAt = expiresAt;
    }
  }

  private static class TokenBundle {
    final String accessToken;
    final long accessExpiresAt;
    final long refreshExpiresAt;

    TokenBundle(String accessToken, long accessExpiresAt, long refreshExpiresAt) {
      this.accessToken = accessToken;
      this.accessExpiresAt = accessExpiresAt;
      this.refreshExpiresAt = refreshExpiresAt;
    }
  }
}
