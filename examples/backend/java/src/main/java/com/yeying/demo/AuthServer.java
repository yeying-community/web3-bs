package com.yeying.demo;

import static spark.Spark.*;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
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

  private static final int PORT = (int) getEnvLong("PORT", 4001);

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
      return jsonResponse(res, ok(data));
    });

    get("/api/v1/private/profile", (req, res) -> {
      String auth = req.headers("Authorization");
      if (auth == null || !auth.toLowerCase().startsWith("bearer ")) {
        res.status(401);
        return jsonResponse(res, fail(401, "Missing access token"));
      }

      String token = auth.substring(7).trim();
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

    System.out.println("Auth server running at http://localhost:" + PORT);
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
    byte[] msgHash = Sign.getEthereumMessageHash(message.getBytes(StandardCharsets.UTF_8));
    String address = "0x" + Keys.getAddress(Sign.signedMessageToKey(msgHash, sigData));
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

  private static String randomHex(int bytes) {
    SecureRandom random = new SecureRandom();
    byte[] buffer = new byte[bytes];
    random.nextBytes(buffer);
    return Numeric.toHexStringNoPrefix(buffer);
  }

  private static Set<String> allowedOrigins(int port) {
    String[] defaults = new String[] {
        "http://localhost:" + port,
        "http://127.0.0.1:" + port,
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "http://localhost:8001",
        "http://127.0.0.1:8001",
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
