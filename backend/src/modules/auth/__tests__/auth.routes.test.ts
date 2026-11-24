import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import request from "supertest";
import type { Request, Response, NextFunction } from "express";

const mockAuthService = vi.hoisted(() => ({
  register: vi.fn(),
  login: vi.fn(),
  refresh: vi.fn(),
  logout: vi.fn(),
  getMe: vi.fn(),
}));

const mockPrisma = vi.hoisted(() => ({
  session: {
    findUnique: vi.fn(),
  },
}));

vi.mock("../../../config/prisma.js", () => ({
  default: mockPrisma,
  prisma: mockPrisma,
}));

// Bypass rate limiters in route tests so multiple test requests never trip 429;
// rate limiter logic is tested separately in authRateLimiter.test.ts.
vi.mock("../../../middlewares/authRateLimiter.js", () => ({
  registerRateLimiter: (_req: Request, _res: Response, next: NextFunction) => next(),
  loginRateLimiter: (_req: Request, _res: Response, next: NextFunction) => next(),
  refreshRateLimiter: (_req: Request, _res: Response, next: NextFunction) => next(),
  authRateLimiter: (_req: Request, _res: Response, next: NextFunction) => next(),
  default: (_req: Request, _res: Response, next: NextFunction) => next(),
}));

vi.mock("../auth.service.js", () => ({
  authService: mockAuthService,
}));

import app from "../../../app.js";
import { generateAccessToken } from "../../../common/utils/token.js";
import { ConflictError, ForbiddenError, UnauthorizedError } from "../../../utils/errors.js";

describe("Auth Routes (/api/auth)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.stubEnv("JWT_ACCESS_SECRET", "test-secret-key-at-least-32-chars-long!!");
    vi.stubEnv("JWT_ISSUER", "sikka-exchange");
    vi.stubEnv("JWT_AUDIENCE", "sikka-api");
  });

  afterEach(() => {
    vi.unstubAllEnvs();
  });

  describe("POST /api/auth/register", () => {
    it("returns 400 with field errors when payload fails Zod validation", async () => {
      const res = await request(app)
        .post("/api/auth/register")
        .send({ email: "not-an-email", password: "short" });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      expect(res.body.message).toBe("Validation failed");
      expect(res.body.errors).toHaveProperty("email");
      expect(res.body.errors).toHaveProperty("password");
      expect(mockAuthService.register).not.toHaveBeenCalled();
    });

    it("returns 201 and normalizes email before calling authService.register", async () => {
      const userPayload = {
        id: "user-1",
        email: "alice@example.com",
        username: "alice",
        status: "PENDING_VERIFICATION",
        createdAt: "2026-01-01T00:00:00.000Z",
      };
      mockAuthService.register.mockResolvedValue(userPayload);

      const res = await request(app)
        .post("/api/auth/register")
        .send({
          email: "  Alice@Example.com ",
          password: "StrongPassword123!",
          username: "alice",
        });

      expect(res.status).toBe(201);
      expect(res.body.success).toBe(true);
      expect(res.body.data.user).toEqual(userPayload);
      expect(mockAuthService.register).toHaveBeenCalledWith({
        email: "alice@example.com",
        password: "StrongPassword123!",
        username: "alice",
      });
    });

    it("returns 409 when authService.register throws ConflictError", async () => {
      mockAuthService.register.mockRejectedValue(
        new ConflictError("An account with this email already exists"),
      );

      const res = await request(app)
        .post("/api/auth/register")
        .send({
          email: "alice@example.com",
          password: "StrongPassword123!",
        });

      expect(res.status).toBe(409);
      expect(res.body).toEqual({
        success: false,
        message: "An account with this email already exists",
      });
    });

    it("returns 500 via global error handler when an unexpected error occurs", async () => {
      vi.spyOn(console, "error").mockImplementation(() => { });
      mockAuthService.register.mockRejectedValue(new Error("DB connection lost"));

      const res = await request(app)
        .post("/api/auth/register")
        .send({
          email: "alice@example.com",
          password: "StrongPassword123!",
        });

      expect(res.status).toBe(500);
      expect(res.body).toEqual({
        success: false,
        message: "Internal server error",
      });
    });
  });

  describe("POST /api/auth/login", () => {
    it("returns 400 when email is invalid or password is empty", async () => {
      const res = await request(app)
        .post("/api/auth/login")
        .send({ email: "bad", password: "" });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      expect(res.body.errors).toHaveProperty("email");
      expect(res.body.errors).toHaveProperty("password");
      expect(mockAuthService.login).not.toHaveBeenCalled();
    });

    it("returns 200 with accessToken in JSON and sets refresh_token as httpOnly cookie", async () => {
      const loginPayload = {
        user: {
          id: "user-1",
          email: "alice@example.com",
          username: "alice",
          status: "ACTIVE",
          createdAt: "2026-01-01T00:00:00.000Z",
        },
        tokens: {
          accessToken: "jwt-access-token",
          refreshToken: "raw-refresh-token",
        },
      };
      mockAuthService.login.mockResolvedValue(loginPayload);

      const res = await request(app)
        .post("/api/auth/login")
        .set("User-Agent", "TestClient/2.0")
        .send({ email: " ALICE@Example.com ", password: "StrongPassword123!" });

      expect(res.status).toBe(200);
      expect(res.body).toEqual({
        success: true,
        message: "Login successful",
        data: {
          user: loginPayload.user,
          accessToken: "jwt-access-token",
        },
      });
      expect(res.body.data.refreshToken).toBeUndefined();

      const setCookie = res.headers["set-cookie"]?.[0] ?? "";
      expect(setCookie).toContain("refresh_token=raw-refresh-token");
      expect(setCookie).toContain("HttpOnly");
      expect(setCookie).toContain("SameSite=Strict");
      expect(setCookie).toContain("Path=/api/auth");

      expect(mockAuthService.login).toHaveBeenCalledWith({
        email: "alice@example.com",
        password: "StrongPassword123!",
        userAgent: "TestClient/2.0",
        ipAddress: expect.any(String),
      });
    });

    it("returns 401 when authService.login throws UnauthorizedError", async () => {
      mockAuthService.login.mockRejectedValue(new UnauthorizedError("Invalid email or password"));

      const res = await request(app)
        .post("/api/auth/login")
        .send({ email: "alice@example.com", password: "wrong" });

      expect(res.status).toBe(401);
      expect(res.body).toEqual({
        success: false,
        message: "Invalid email or password",
      });
    });

    it("returns 403 when account is PENDING_VERIFICATION or CLOSED", async () => {
      mockAuthService.login.mockRejectedValue(
        new ForbiddenError("Please verify your email address before logging in."),
      );

      const res = await request(app)
        .post("/api/auth/login")
        .send({ email: "pending@example.com", password: "StrongPassword123!" });

      expect(res.status).toBe(403);
      expect(res.body).toEqual({
        success: false,
        message: "Please verify your email address before logging in.",
      });
    });
  });

  describe("POST /api/auth/refresh", () => {
    it("returns 401 and clears cookie when refresh_token cookie is missing", async () => {
      const res = await request(app).post("/api/auth/refresh");

      expect(res.status).toBe(401);
      expect(res.body).toEqual({
        success: false,
        message: "Refresh token is missing",
      });
      expect(mockAuthService.refresh).not.toHaveBeenCalled();
    });

    it("rotates refresh_token httpOnly cookie and returns new accessToken on valid cookie", async () => {
      const refreshPayload = {
        user: {
          id: "user-1",
          email: "alice@example.com",
          username: "alice",
          status: "ACTIVE",
          createdAt: "2026-01-01T00:00:00.000Z",
        },
        tokens: {
          accessToken: "new-access-token",
          refreshToken: "new-refresh-token",
        },
      };
      mockAuthService.refresh.mockResolvedValue(refreshPayload);

      const res = await request(app)
        .post("/api/auth/refresh")
        .set("Cookie", ["refresh_token=old-refresh-token"])
        .set("User-Agent", "TestClient/2.0");

      expect(res.status).toBe(200);
      expect(res.body).toEqual({
        success: true,
        message: "Token refreshed successfully",
        data: {
          user: refreshPayload.user,
          accessToken: "new-access-token",
        },
      });

      const setCookie = res.headers["set-cookie"]?.[0] ?? "";
      expect(setCookie).toContain("refresh_token=new-refresh-token");
      expect(setCookie).toContain("HttpOnly");

      expect(mockAuthService.refresh).toHaveBeenCalledWith({
        refreshToken: "old-refresh-token",
        userAgent: "TestClient/2.0",
        ipAddress: expect.any(String),
      });
    });

    it("returns 401 and clears cookie when reuse is detected", async () => {
      mockAuthService.refresh.mockRejectedValue(
        new UnauthorizedError("Refresh token reuse detected. Please log in again."),
      );

      const res = await request(app)
        .post("/api/auth/refresh")
        .set("Cookie", ["refresh_token=reused-token"]);

      expect(res.status).toBe(401);
      expect(res.body).toEqual({
        success: false,
        message: "Refresh token reuse detected. Please log in again.",
      });
      const setCookie = res.headers["set-cookie"]?.[0] ?? "";
      expect(setCookie).toContain("refresh_token=;");
    });
  });

  describe("POST /api/auth/logout", () => {
    it("revokes session and clears refresh_token cookie when cookie is present", async () => {
      mockAuthService.logout.mockResolvedValue(undefined);

      const res = await request(app)
        .post("/api/auth/logout")
        .set("Cookie", ["refresh_token=active-refresh-token"]);

      expect(res.status).toBe(200);
      expect(res.body).toEqual({
        success: true,
        message: "Logged out successfully",
      });
      expect(mockAuthService.logout).toHaveBeenCalledWith("active-refresh-token");

      const setCookie = res.headers["set-cookie"]?.[0] ?? "";
      expect(setCookie).toContain("refresh_token=;");
      expect(setCookie).toContain("Path=/api/auth");
      expect(setCookie).toContain("HttpOnly");
    });

    it("is idempotent and clears cookie even when refresh_token cookie is absent", async () => {
      const res = await request(app).post("/api/auth/logout");

      expect(res.status).toBe(200);
      expect(res.body).toEqual({
        success: true,
        message: "Logged out successfully",
      });
      expect(mockAuthService.logout).not.toHaveBeenCalled();

      const setCookie = res.headers["set-cookie"]?.[0] ?? "";
      expect(setCookie).toContain("refresh_token=;");
    });
  });

  describe("GET /api/auth/me", () => {
    it("returns 401 when Authorization header is missing", async () => {
      const res = await request(app).get("/api/auth/me");

      expect(res.status).toBe(401);
      expect(res.body).toEqual({
        success: false,
        message: "Missing or invalid authorization header",
      });
    });

    it("returns 401 when session has been revoked after logout", async () => {
      const token = await generateAccessToken({ userId: "user-1", sessionId: "sess-revoked" });
      mockPrisma.session.findUnique.mockResolvedValue({
        id: "sess-revoked",
        userId: "user-1",
        revokedAt: new Date(),
        expiresAt: new Date(Date.now() + 60_000),
        user: { id: "user-1", status: "ACTIVE" },
      });

      const res = await request(app)
        .get("/api/auth/me")
        .set("Authorization", `Bearer ${token}`);

      expect(res.status).toBe(401);
      expect(res.body.message).toBe("Session has been revoked");
    });

    it("returns 200 and user profile for valid ACTIVE and SUSPENDED sessions", async () => {
      const token = await generateAccessToken({ userId: "user-2", sessionId: "sess-2" });
      mockPrisma.session.findUnique.mockResolvedValue({
        id: "sess-2",
        userId: "user-2",
        revokedAt: null,
        expiresAt: new Date(Date.now() + 60_000),
        user: { id: "user-2", status: "SUSPENDED" },
      });
      const userProfile = {
        id: "user-2",
        email: "suspended@example.com",
        username: "suspended_user",
        status: "SUSPENDED",
        createdAt: "2026-01-01T00:00:00.000Z",
      };
      mockAuthService.getMe.mockResolvedValue(userProfile);

      const res = await request(app)
        .get("/api/auth/me")
        .set("Authorization", `Bearer ${token}`);

      expect(res.status).toBe(200);
      expect(res.body).toEqual({
        success: true,
        data: { user: userProfile },
      });
      expect(mockAuthService.getMe).toHaveBeenCalledWith("user-2");
    });
  });
});
