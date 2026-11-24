import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import express, { type Request, type Response, type NextFunction } from "express";
import request from "supertest";

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
import { requireTradingAccess } from "../requireTradingAccess.js";
import { generateAccessToken } from "../../common/utils/token.js";
import { AppError, ForbiddenError, UnauthorizedError } from "../../utils/errors.js";

describe("requireTradingAccess middleware", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.stubEnv("JWT_ACCESS_SECRET", "test-secret-key-at-least-32-chars-long!!");
    vi.stubEnv("JWT_ISSUER", "sikka-exchange");
    vi.stubEnv("JWT_AUDIENCE", "sikka-api");
  });

  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("allows ACTIVE users to proceed", () => {
    const req = { auth: { userId: "u1", sessionId: "s1", status: "ACTIVE" } } as Request;
    const next = vi.fn() as unknown as NextFunction;

    requireTradingAccess(req, {} as Response, next);

    expect(next).toHaveBeenCalledWith();
  });

  it("blocks SUSPENDED users with ForbiddenError", () => {
    const req = { auth: { userId: "u1", sessionId: "s1", status: "SUSPENDED" } } as Request;
    const next = vi.fn() as unknown as NextFunction;

    requireTradingAccess(req, {} as Response, next);

    expect(next).toHaveBeenCalledWith(expect.any(ForbiddenError));
  });

  it("blocks CLOSED and unauthenticated requests", () => {
    const closedReq = { auth: { userId: "u1", sessionId: "s1", status: "CLOSED" } } as Request;
    const nextClosed = vi.fn() as unknown as NextFunction;
    requireTradingAccess(closedReq, {} as Response, nextClosed);
    expect(nextClosed).toHaveBeenCalledWith(expect.any(ForbiddenError));

    const unauthReq = {} as Request;
    const nextUnauth = vi.fn() as unknown as NextFunction;
    requireTradingAccess(unauthReq, {} as Response, nextUnauth);
    expect(nextUnauth).toHaveBeenCalledWith(expect.any(UnauthorizedError));
  });

  it("allows a SUSPENDED user to read account info while blocking trading routes", async () => {
    const app = express();
    app.get("/account", authenticate, (req, res) => {
      res.status(200).json({ success: true, userId: req.auth?.userId, status: req.auth?.status });
    });
    app.post("/trade", authenticate, requireTradingAccess, (_req, res) => {
      res.status(201).json({ success: true });
    });
    app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
      if (err instanceof AppError) {
        res.status(err.statusCode).json({ success: false, message: err.message });
        return;
      }
      res.status(500).json({ success: false });
    });

    const suspendedToken = await generateAccessToken({
      userId: "user-suspended",
      sessionId: "sess-suspended",
    });

    mockPrisma.session.findUnique.mockResolvedValue({
      id: "sess-suspended",
      userId: "user-suspended",
      revokedAt: null,
      expiresAt: new Date(Date.now() + 60_000),
      user: { id: "user-suspended", status: "SUSPENDED" },
    });

    const accountRes = await request(app)
      .get("/account")
      .set("Authorization", `Bearer ${suspendedToken}`);
    expect(accountRes.status).toBe(200);
    expect(accountRes.body).toEqual({
      success: true,
      userId: "user-suspended",
      status: "SUSPENDED",
    });

    const tradeRes = await request(app)
      .post("/trade")
      .set("Authorization", `Bearer ${suspendedToken}`);
    expect(tradeRes.status).toBe(403);
    expect(tradeRes.body.message).toContain("suspended");
  });
});

