import crypto from "node:crypto";
import { SignJWT, jwtVerify, type JWTPayload } from "jose";

const ACCESS_TOKEN_TTL = "15m";
const REFRESH_TOKEN_BYTES = 32; // 256 bits

export interface AccessTokenInput {
  userId: string;
  sessionId: string;
}

export interface AccessTokenPayload extends JWTPayload {
  sub: string;
  sid: string;
}

function getJwtConfig() {
  const secret = process.env.JWT_ACCESS_SECRET;
  const issuer = process.env.JWT_ISSUER;
  const audience = process.env.JWT_AUDIENCE;

  if (!secret || secret.length < 32) {
    throw new Error("JWT_ACCESS_SECRET must be configured and at least 32 characters long");
  }
  if (!issuer || !audience) {
    throw new Error("JWT_ISSUER and JWT_AUDIENCE must be configured");
  }

  return {
    secretKey: new TextEncoder().encode(secret),
    issuer,
    audience,
  };
}

// Generates a signed HS256 JWT access token valid for 15 minutes.

export async function generateAccessToken(input: AccessTokenInput): Promise<string> {
  const { secretKey, issuer, audience } = getJwtConfig();

  return new SignJWT({ sid: input.sessionId })
    .setProtectedHeader({ alg: "HS256" })
    .setSubject(input.userId)
    .setIssuedAt()
    .setIssuer(issuer)
    .setAudience(audience)
    .setExpirationTime(ACCESS_TOKEN_TTL)
    .sign(secretKey);
}

// Verifies an access token signature, expiration, issuer, and audience.

export async function verifyAccessToken(token: string): Promise<AccessTokenPayload> {
  const { secretKey, issuer, audience } = getJwtConfig();

  const { payload } = await jwtVerify(token, secretKey, {
    issuer,
    audience,
    algorithms: ["HS256"],
  });

  if (typeof payload.sub !== "string" || typeof payload.sid !== "string") {
    throw new Error("Malformed access token claims");
  }

  return payload as AccessTokenPayload;
}

// Generates a cryptographically secure 256-bit random refresh token.

export function generateRefreshToken(): string {
  return crypto.randomBytes(REFRESH_TOKEN_BYTES).toString("base64url");
}

//  Deterministically SHA-256 hashes a refresh token for O(1) indexed DB lookups.

export function hashRefreshToken(token: string): string {
  return crypto.createHash("sha256").update(token).digest("hex");
}

