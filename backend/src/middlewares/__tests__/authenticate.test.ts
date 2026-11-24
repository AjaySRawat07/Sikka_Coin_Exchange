import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import type { Request, Response, NextFunction } from "express";
import { SignJWT } from "jose";

const mockPrisma = vi.hoisted(() => ({
  session: {
    findUnique: vi.fn(),
  },
}));

vi.mock("../../config/prisma.js", () => ({
  default: mockPrisma,
  prisma: mockPrisma,
}));

import { authenticate } from "../authenticate.js";
import { generateAccessToken } from "../../common/utils/token.js";
import { ForbiddenError, UnauthorizedError } from "../../utils/errors.js";

function createMockReq(authHeader?: string): Request {
  return {
    headers: authHeader !== undefined ? { authorization: authHeader } : {},
  } as Request;
}

describe("authenticate middleware", () => {
  const secret = "test-secret-key-at-least-32-chars-long!!";

  beforeEach(() => {
    vi.clearAllMocks();
    vi.stubEnv("JWT_ACCESS_SECRET", secret);
    vi.stubEnv("JWT_ISSUER", "sikka-exchange");
    vi.stubEnv("JWT_AUDIENCE", "sikka-api");
  });

  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("rejects with UnauthorizedError when Authorization header is missing", async () => {
    const req = createMockReq();
    const next = vi.fn() as unknown as NextFunction;

    await authenticate(req, {} as Response, next);

    expect(next).toHaveBeenCalledWith(expect.any(UnauthorizedError));
    expect(req.auth).toBeUndefined();
  });

  it("rejects with UnauthorizedError when token is invalid or tampered", async () => {
    const req = createMockReq("Bearer invalid.jwt.token");
    const next = vi.fn() as unknown as NextFunction;

    await authenticate(req, {} as Response, next);

    expect(next).toHaveBeenCalledWith(expect.any(UnauthorizedError));
    expect(mockPrisma.session.findUnique).not.toHaveBeenCalled();
  });

  it("rejects with UnauthorizedError when JWT is expired", async () => {
    const expiredJwt = await new SignJWT({ sid: "sess-1" })
      .setProtectedHeader({ alg: "HS256" })
      .setSubject("user-1")
      .setIssuer("sikka-exchange")
      .setAudience("sikka-api")
      .setExpirationTime(Math.floor(Date.now() / 1000) - 60)
      .sign(new TextEncoder().encode(secret));

    const req = createMockReq(`Bearer ${expiredJwt}`);
    const next = vi.fn() as unknown as NextFunction;

    await authenticate(req, {} as Response, next);

    expect(next).toHaveBeenCalledWith(expect.any(UnauthorizedError));
    expect(mockPrisma.session.findUnique).not.toHaveBeenCalled();
  });

  it("rejects with UnauthorizedError when session does not exist in PostgreSQL", async () => {
    const token = await generateAccessToken({ userId: "user-1", sessionId: "sess-missing" });
    mockPrisma.session.findUnique.mockResolvedValue(null);

    const req = createMockReq(`Bearer ${token}`);
    const next = vi.fn() as unknown as NextFunction;

    await authenticate(req, {} as Response, next);

    expect(next).toHaveBeenCalledWith(expect.any(UnauthorizedError));
  });

  it("rejects with UnauthorizedError when session has been revoked (e.g. after logout)", async () => {
    const token = await generateAccessToken({ userId: "user-1", sessionId: "sess-revoked" });
    mockPrisma.session.findUnique.mockResolvedValue({
      id: "sess-revoked",
      userId: "user-1",
      revokedAt: new Date(Date.now() - 1000),
      expiresAt: new Date(Date.now() + 60_000),
      user: { id: "user-1", status: "ACTIVE" },
    });

    const req = createMockReq(`Bearer ${token}`);
    const next = vi.fn() as unknown as NextFunction;

    await authenticate(req, {} as Response, next);

    const err = (next as unknown as ReturnType<typeof vi.fn>).mock.calls[0]?.[0];
    expect(err).toBeInstanceOf(UnauthorizedError);
    expect(err.message).toBe("Session has been revoked");
  });

  it("rejects with UnauthorizedError when session is expired in PostgreSQL", async () => {
    const token = await generateAccessToken({ userId: "user-1", sessionId: "sess-expired" });
    mockPrisma.session.findUnique.mockResolvedValue({
      id: "sess-expired",
      userId: "user-1",
      revokedAt: null,
      expiresAt: new Date(Date.now() - 1000),
      user: { id: "user-1", status: "ACTIVE" },
    });

    const req = createMockReq(`Bearer ${token}`);
    const next = vi.fn() as unknown as NextFunction;

    await authenticate(req, {} as Response, next);

    expect(next).toHaveBeenCalledWith(expect.any(UnauthorizedError));
  });

  it("rejects with ForbiddenError when account is CLOSED", async () => {
    const token = await generateAccessToken({ userId: "user-1", sessionId: "sess-1" });
    mockPrisma.session.findUnique.mockResolvedValue({
      id: "sess-1",
      userId: "user-1",
      revokedAt: null,
      expiresAt: new Date(Date.now() + 60_000),
      user: { id: "user-1", status: "CLOSED" },
    });

    const req = createMockReq(`Bearer ${token}`);
    const next = vi.fn() as unknown as NextFunction;

    await authenticate(req, {} as Response, next);

    expect(next).toHaveBeenCalledWith(expect.any(ForbiddenError));
  });

  it("attaches req.auth and calls next() for a valid ACTIVE session", async () => {
    const token = await generateAccessToken({ userId: "user-1", sessionId: "sess-1" });
    mockPrisma.session.findUnique.mockResolvedValue({
      id: "sess-1",
      userId: "user-1",
      revokedAt: null,
      expiresAt: new Date(Date.now() + 60_000),
      user: { id: "user-1", status: "ACTIVE" },
    });

    const req = createMockReq(`Bearer ${token}`);
    const next = vi.fn() as unknown as NextFunction;

    await authenticate(req, {} as Response, next);

    expect(next).toHaveBeenCalledWith();
    expect(req.auth).toEqual({
      userId: "user-1",
      sessionId: "sess-1",
      status: "ACTIVE",
    });
  });

  it("attaches req.auth and allows SUSPENDED users to authenticate", async () => {
    const token = await generateAccessToken({ userId: "user-2", sessionId: "sess-2" });
    mockPrisma.session.findUnique.mockResolvedValue({
      id: "sess-2",
      userId: "user-2",
      revokedAt: null,
      expiresAt: new Date(Date.now() + 60_000),
      user: { id: "user-2", status: "SUSPENDED" },
    });

    const req = createMockReq(`Bearer ${token}`);
    const next = vi.fn() as unknown as NextFunction;

    await authenticate(req, {} as Response, next);

    expect(next).toHaveBeenCalledWith();
    expect(req.auth).toEqual({
      userId: "user-2",
      sessionId: "sess-2",
      status: "SUSPENDED",
    });
  });
});

