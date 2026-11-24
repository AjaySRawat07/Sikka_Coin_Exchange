import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import argon2 from "argon2";
import { Prisma } from "@prisma/client";

const mockPrisma = vi.hoisted(() => ({
  user: {
    findUnique: vi.fn(),
    create: vi.fn(),
    update: vi.fn(),
  },
  session: {
    findUnique: vi.fn(),
    create: vi.fn(),
    update: vi.fn(),
    updateMany: vi.fn(),
  },
  $transaction: vi.fn(),
}));

vi.mock("../../../config/prisma.js", () => ({
  default: mockPrisma,
  prisma: mockPrisma,
}));

import { authService } from "../auth.service.js";
import { hashRefreshToken, verifyAccessToken } from "../../../common/utils/token.js";
import { ConflictError, ForbiddenError, UnauthorizedError } from "../../../utils/errors.js";

describe("AuthService", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    vi.stubEnv("JWT_ACCESS_SECRET", "test-secret-key-at-least-32-chars-long!!");
    vi.stubEnv("JWT_ISSUER", "sikka-exchange");
    vi.stubEnv("JWT_AUDIENCE", "sikka-api");
    mockPrisma.$transaction.mockImplementation((arg: unknown) => {
      if (Array.isArray(arg)) return Promise.all(arg);
      if (typeof arg === "function") return (arg as (tx: typeof mockPrisma) => unknown)(mockPrisma);
      throw new Error("Unexpected $transaction argument");
    });
  });

  afterEach(() => {
    vi.unstubAllEnvs();
  });

  describe("register", () => {
    it("normalizes email, hashes password with Argon2id, and returns user without passwordHash", async () => {
      mockPrisma.user.findUnique.mockResolvedValue(null);
      const createdUser = {
        id: "user-1",
        email: "alice@example.com",
        username: "alice",
        status: "PENDING_VERIFICATION",
        createdAt: new Date("2026-01-01T00:00:00Z"),
      };
      mockPrisma.user.create.mockResolvedValue(createdUser);

      const hashSpy = vi.spyOn(argon2, "hash");

      const result = await authService.register({
        email: "  Alice@Example.COM ",
        password: "StrongPassword123!",
        username: "alice",
      });

      expect(mockPrisma.user.findUnique).toHaveBeenNthCalledWith(1, {
        where: { email: "alice@example.com" },
        select: { id: true },
      });
      expect(hashSpy).toHaveBeenCalledWith(
        "StrongPassword123!",
        expect.objectContaining({ type: argon2.argon2id }),
      );

      const createArg = mockPrisma.user.create.mock.calls[0]?.[0];
      expect(createArg.data.email).toBe("alice@example.com");
      expect(createArg.data.passwordHash).toMatch(/^\$argon2id\$/);
      expect(createArg.data.passwordHash).not.toBe("StrongPassword123!");
      expect(createArg.data.status).toBe("PENDING_VERIFICATION");
      expect(createArg.select.passwordHash).toBeUndefined();

      expect(result).toEqual(createdUser);
    });

    it("throws ConflictError and skips Argon2 hashing when email already exists", async () => {
      mockPrisma.user.findUnique.mockResolvedValueOnce({ id: "existing-id" });
      const hashSpy = vi.spyOn(argon2, "hash");

      await expect(
        authService.register({
          email: "alice@example.com",
          password: "StrongPassword123!",
        }),
      ).rejects.toThrow(ConflictError);

      expect(hashSpy).not.toHaveBeenCalled();
      expect(mockPrisma.user.create).not.toHaveBeenCalled();
    });

    it("throws ConflictError on concurrent duplicate email (Prisma P2002)", async () => {
      mockPrisma.user.findUnique.mockResolvedValue(null);
      const p2002Error = new Prisma.PrismaClientKnownRequestError("Unique constraint failed", {
        code: "P2002",
        clientVersion: "6.19.3",
        meta: { target: ["email"] },
      });
      mockPrisma.user.create.mockRejectedValue(p2002Error);

      await expect(
        authService.register({
          email: "race@example.com",
          password: "StrongPassword123!",
        }),
      ).rejects.toThrow(ConflictError);
    });
  });

  describe("login", () => {
    it("authenticates an ACTIVE user, persists hashed session in transaction, and returns tokens", async () => {
      const passwordHash = await argon2.hash("CorrectPassword123!", {
        type: argon2.argon2id,
        memoryCost: 19456,
        timeCost: 2,
        parallelism: 1,
      });

      mockPrisma.user.findUnique.mockResolvedValue({
        id: "user-1",
        email: "alice@example.com",
        username: "alice",
        passwordHash,
        status: "ACTIVE",
        createdAt: new Date("2026-01-01T00:00:00Z"),
      });
      mockPrisma.user.update.mockResolvedValue({});
      mockPrisma.session.create.mockResolvedValue({ id: "session-99" });

      const result = await authService.login({
        email: " ALICE@Example.com ",
        password: "CorrectPassword123!",
        userAgent: "VitestBrowser/1.0",
        ipAddress: "203.0.113.5",
      });

      expect(mockPrisma.$transaction).toHaveBeenCalledTimes(1);
      expect(mockPrisma.user.update).toHaveBeenCalledWith({
        where: { id: "user-1" },
        data: { lastLoginAt: expect.any(Date) },
      });

      const sessionCreateArg = mockPrisma.session.create.mock.calls[0]?.[0];
      expect(sessionCreateArg.data.userId).toBe("user-1");
      expect(sessionCreateArg.data.tokenHash).toBe(hashRefreshToken(result.tokens.refreshToken));
      expect(sessionCreateArg.data.tokenHash).not.toBe(result.tokens.refreshToken);
      expect(sessionCreateArg.data.userAgent).toBe("VitestBrowser/1.0");
      expect(sessionCreateArg.data.ipAddress).toBe("203.0.113.5");
      expect(sessionCreateArg.data.expiresAt).toBeInstanceOf(Date);

      const jwtPayload = await verifyAccessToken(result.tokens.accessToken);
      expect(jwtPayload.sub).toBe("user-1");
      expect(jwtPayload.sid).toBe("session-99");

      expect(result.user).toEqual({
        id: "user-1",
        email: "alice@example.com",
        username: "alice",
        status: "ACTIVE",
        createdAt: new Date("2026-01-01T00:00:00Z"),
      });
      expect(result.user).not.toHaveProperty("passwordHash");
    });

    it("allows SUSPENDED users to log in and creates a session", async () => {
      const passwordHash = await argon2.hash("CorrectPassword123!", {
        type: argon2.argon2id,
        memoryCost: 19456,
        timeCost: 2,
        parallelism: 1,
      });

      mockPrisma.user.findUnique.mockResolvedValue({
        id: "user-2",
        email: "suspended@example.com",
        username: null,
        passwordHash,
        status: "SUSPENDED",
        createdAt: new Date("2026-01-01T00:00:00Z"),
      });
      mockPrisma.user.update.mockResolvedValue({});
      mockPrisma.session.create.mockResolvedValue({ id: "session-100" });

      const result = await authService.login({
        email: "suspended@example.com",
        password: "CorrectPassword123!",
      });

      expect(result.user.status).toBe("SUSPENDED");
      expect(result.tokens.accessToken).toBeTruthy();
      expect(result.tokens.refreshToken).toBeTruthy();
    });

    it("throws UnauthorizedError for nonexistent email AND runs dummy Argon2 verification", async () => {
      mockPrisma.user.findUnique.mockResolvedValue(null);
      const verifySpy = vi.spyOn(argon2, "verify");

      await expect(
        authService.login({
          email: "nobody@example.com",
          password: "AnyPassword123!",
        }),
      ).rejects.toThrow(UnauthorizedError);

      expect(verifySpy).toHaveBeenCalledTimes(1);
      expect(mockPrisma.$transaction).not.toHaveBeenCalled();
      expect(mockPrisma.session.create).not.toHaveBeenCalled();
    });

    it("throws UnauthorizedError when password is wrong", async () => {
      const passwordHash = await argon2.hash("CorrectPassword123!", {
        type: argon2.argon2id,
        memoryCost: 19456,
        timeCost: 2,
        parallelism: 1,
      });

      mockPrisma.user.findUnique.mockResolvedValue({
        id: "user-1",
        email: "alice@example.com",
        username: "alice",
        passwordHash,
        status: "ACTIVE",
        createdAt: new Date("2026-01-01T00:00:00Z"),
      });

      await expect(
        authService.login({
          email: "alice@example.com",
          password: "WrongPassword!",
        }),
      ).rejects.toThrow(UnauthorizedError);

      expect(mockPrisma.$transaction).not.toHaveBeenCalled();
      expect(mockPrisma.session.create).not.toHaveBeenCalled();
    });

    it("throws ForbiddenError for PENDING_VERIFICATION only after password succeeds", async () => {
      const passwordHash = await argon2.hash("CorrectPassword123!", {
        type: argon2.argon2id,
        memoryCost: 19456,
        timeCost: 2,
        parallelism: 1,
      });

      mockPrisma.user.findUnique.mockResolvedValue({
        id: "user-3",
        email: "pending@example.com",
        username: null,
        passwordHash,
        status: "PENDING_VERIFICATION",
        createdAt: new Date("2026-01-01T00:00:00Z"),
      });

      await expect(
        authService.login({
          email: "pending@example.com",
          password: "CorrectPassword123!",
        }),
      ).rejects.toThrow(ForbiddenError);

      await expect(
        authService.login({
          email: "pending@example.com",
          password: "WrongPassword!",
        }),
      ).rejects.toThrow(UnauthorizedError);

      expect(mockPrisma.session.create).not.toHaveBeenCalled();
    });

    it("throws ForbiddenError for CLOSED accounts only after password succeeds", async () => {
      const passwordHash = await argon2.hash("CorrectPassword123!", {
        type: argon2.argon2id,
        memoryCost: 19456,
        timeCost: 2,
        parallelism: 1,
      });

      mockPrisma.user.findUnique.mockResolvedValue({
        id: "user-4",
        email: "closed@example.com",
        username: null,
        passwordHash,
        status: "CLOSED",
        createdAt: new Date("2026-01-01T00:00:00Z"),
      });

      await expect(
        authService.login({
          email: "closed@example.com",
          password: "CorrectPassword123!",
        }),
      ).rejects.toThrow(ForbiddenError);

      await expect(
        authService.login({
          email: "closed@example.com",
          password: "WrongPassword!",
        }),
      ).rejects.toThrow(UnauthorizedError);

      expect(mockPrisma.session.create).not.toHaveBeenCalled();
    });
  });

  describe("refresh", () => {
    const activeUser = {
      id: "user-1",
      email: "alice@example.com",
      username: "alice",
      status: "ACTIVE" as const,
      createdAt: new Date("2026-01-01T00:00:00Z"),
    };

    it("rotates a valid refresh token, links replacedById, and returns a new token pair", async () => {
      const rawToken = "valid-raw-refresh-token";
      mockPrisma.session.findUnique.mockResolvedValue({
        id: "sess-1",
        userId: "user-1",
        familyId: "fam-1",
        replacedById: null,
        revokedAt: null,
        expiresAt: new Date(Date.now() + 60_000),
        user: activeUser,
      });
      mockPrisma.session.updateMany.mockResolvedValue({ count: 1 });
      mockPrisma.session.create.mockResolvedValue({ id: "sess-2" });
      mockPrisma.session.update.mockResolvedValue({});

      const result = await authService.refresh({
        refreshToken: rawToken,
        userAgent: "Chrome/120",
        ipAddress: "198.51.100.1",
      });

      expect(mockPrisma.session.findUnique).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { tokenHash: hashRefreshToken(rawToken) },
        }),
      );
      expect(mockPrisma.session.updateMany).toHaveBeenCalledWith({
        where: { id: "sess-1", revokedAt: null },
        data: { revokedAt: expect.any(Date), lastUsedAt: expect.any(Date) },
      });
      expect(mockPrisma.session.create).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({
            userId: "user-1",
            familyId: "fam-1",
            tokenHash: hashRefreshToken(result.tokens.refreshToken),
          }),
        }),
      );
      expect(mockPrisma.session.update).toHaveBeenCalledWith({
        where: { id: "sess-1" },
        data: { replacedById: "sess-2" },
      });
      expect(result.tokens.refreshToken).not.toBe(rawToken);

      const payload = await verifyAccessToken(result.tokens.accessToken);
      expect(payload.sub).toBe("user-1");
      expect(payload.sid).toBe("sess-2");
    });

    it("detects reuse of an already-rotated token and revokes the entire session family", async () => {
      mockPrisma.session.findUnique.mockResolvedValue({
        id: "sess-1",
        userId: "user-1",
        familyId: "fam-compromised",
        replacedById: "sess-2",
        revokedAt: new Date(Date.now() - 10_000),
        expiresAt: new Date(Date.now() + 60_000),
        user: activeUser,
      });
      mockPrisma.session.updateMany.mockResolvedValue({ count: 1 });

      await expect(authService.refresh({ refreshToken: "replayed-token" })).rejects.toThrow(
        "Refresh token reuse detected",
      );

      expect(mockPrisma.session.updateMany).toHaveBeenCalledWith({
        where: { familyId: "fam-compromised", revokedAt: null },
        data: { revokedAt: expect.any(Date) },
      });
      expect(mockPrisma.session.create).not.toHaveBeenCalled();
    });

    it("revokes the entire family if a concurrent request already rotated the token (claim.count === 0)", async () => {
      mockPrisma.session.findUnique.mockResolvedValue({
        id: "sess-1",
        userId: "user-1",
        familyId: "fam-race",
        replacedById: null,
        revokedAt: null,
        expiresAt: new Date(Date.now() + 60_000),
        user: activeUser,
      });
      mockPrisma.session.updateMany
        .mockResolvedValueOnce({ count: 0 })
        .mockResolvedValueOnce({ count: 1 });

      await expect(authService.refresh({ refreshToken: "race-token" })).rejects.toThrow(
        "Refresh token reuse detected",
      );

      expect(mockPrisma.session.updateMany).toHaveBeenLastCalledWith({
        where: { familyId: "fam-race", revokedAt: null },
        data: { revokedAt: expect.any(Date) },
      });
      expect(mockPrisma.session.create).not.toHaveBeenCalled();
    });

    it("rejects expired tokens and marks the session revoked", async () => {
      mockPrisma.session.findUnique.mockResolvedValue({
        id: "sess-expired",
        userId: "user-1",
        familyId: "fam-1",
        replacedById: null,
        revokedAt: null,
        expiresAt: new Date(Date.now() - 1_000),
        user: activeUser,
      });
      mockPrisma.session.updateMany.mockResolvedValue({ count: 1 });

      await expect(authService.refresh({ refreshToken: "expired-token" })).rejects.toThrow(
        UnauthorizedError,
      );

      expect(mockPrisma.session.updateMany).toHaveBeenCalledWith({
        where: { id: "sess-expired", revokedAt: null },
        data: { revokedAt: expect.any(Date) },
      });
      expect(mockPrisma.session.create).not.toHaveBeenCalled();
    });

    it("rejects and revokes family if user status changed to CLOSED", async () => {
      mockPrisma.session.findUnique.mockResolvedValue({
        id: "sess-1",
        userId: "user-1",
        familyId: "fam-closed",
        replacedById: null,
        revokedAt: null,
        expiresAt: new Date(Date.now() + 60_000),
        user: { ...activeUser, status: "CLOSED" },
      });
      mockPrisma.session.updateMany.mockResolvedValue({ count: 1 });

      await expect(authService.refresh({ refreshToken: "valid-token" })).rejects.toThrow(
        ForbiddenError,
      );

      expect(mockPrisma.session.updateMany).toHaveBeenCalledWith({
        where: { familyId: "fam-closed", revokedAt: null },
        data: { revokedAt: expect.any(Date) },
      });
    });
  });

  describe("logout", () => {
    it("hashes the refresh token and revokes only unrevoked matching sessions", async () => {
      mockPrisma.session.updateMany.mockResolvedValue({ count: 1 });

      await authService.logout("raw-logout-token");

      expect(mockPrisma.session.updateMany).toHaveBeenCalledWith({
        where: {
          tokenHash: hashRefreshToken("raw-logout-token"),
          revokedAt: null,
        },
        data: {
          revokedAt: expect.any(Date),
        },
      });
    });

    it("is idempotent when session does not exist or is already revoked", async () => {
      mockPrisma.session.updateMany.mockResolvedValue({ count: 0 });

      await expect(authService.logout("already-revoked-token")).resolves.toBeUndefined();
    });
  });
});