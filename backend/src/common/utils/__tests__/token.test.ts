import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import {
  generateAccessToken,
  verifyAccessToken,
  generateRefreshToken,
  hashRefreshToken,
} from "../token.js";

describe("Token Utility", () => {
  beforeEach(() => {
    vi.stubEnv("JWT_ACCESS_SECRET", "test-secret-key-at-least-32-chars-long!!");
    vi.stubEnv("JWT_ISSUER", "sikka-exchange");
    vi.stubEnv("JWT_AUDIENCE", "sikka-api");
  });

  afterEach(() => {
    vi.unstubAllEnvs();
  });

  describe("generateAccessToken & verifyAccessToken", () => {
    it("signs and verifies a JWT with sub, sid, iss, aud, and 15m exp", async () => {
      const token = await generateAccessToken({
        userId: "user-123",
        sessionId: "session-456",
      });

      const payload = await verifyAccessToken(token);

      expect(payload.sub).toBe("user-123");
      expect(payload.sid).toBe("session-456");
      expect(payload.iss).toBe("sikka-exchange");
      expect(payload.aud).toBe("sikka-api");
      expect(payload.iat).toBeTypeOf("number");
      expect(payload.exp).toBe((payload.iat as number) + 15 * 60);
    });

    it("rejects tokens signed with a different secret", async () => {
      const token = await generateAccessToken({
        userId: "user-123",
        sessionId: "session-456",
      });

      vi.stubEnv("JWT_ACCESS_SECRET", "completely-different-secret-32-chars-long");

      await expect(verifyAccessToken(token)).rejects.toThrow();
    });

    it("rejects tokens with mismatched audience", async () => {
      const token = await generateAccessToken({
        userId: "user-123",
        sessionId: "session-456",
      });

      vi.stubEnv("JWT_AUDIENCE", "wrong-audience");

      await expect(verifyAccessToken(token)).rejects.toThrow();
    });

    it("fails fast when JWT_ACCESS_SECRET is missing or too short", async () => {
      vi.stubEnv("JWT_ACCESS_SECRET", "too-short");

      await expect(
        generateAccessToken({ userId: "user-123", sessionId: "session-456" }),
      ).rejects.toThrow("JWT_ACCESS_SECRET");
    });
  });

  describe("generateRefreshToken & hashRefreshToken", () => {
    it("generates unique cryptographically random tokens (256-bit base64url)", () => {
      const token1 = generateRefreshToken();
      const token2 = generateRefreshToken();

      expect(token1).not.toBe(token2);
      expect(token1.length).toBe(43); // 32 bytes in base64url without padding = 43 chars
    });

    it("produces deterministic 64-char hex SHA-256 digests", () => {
      const token = generateRefreshToken();
      const hash1 = hashRefreshToken(token);
      const hash2 = hashRefreshToken(token);

      expect(hash1).toBe(hash2);
      expect(hash1).toMatch(/^[a-f0-9]{64}$/);
      expect(hash1).not.toBe(token);
    });
  });
});

