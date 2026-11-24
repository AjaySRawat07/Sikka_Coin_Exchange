import type { Request, Response, NextFunction } from "express";
import type { } from "../types/express.js";
import prisma from "../config/prisma.js";
import { verifyAccessToken } from "../common/utils/token.js";
import { ForbiddenError, UnauthorizedError } from "../utils/errors.js";


export async function authenticate(req: Request, _res: Response, next: NextFunction): Promise<void> {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      next(new UnauthorizedError("Missing or invalid authorization header"));
      return;
    }

    const token = authHeader.slice(7).trim();
    if (!token) {
      next(new UnauthorizedError("Missing access token"));
      return;
    }

    let payload;
    try {
      payload = await verifyAccessToken(token);
    } catch {
      next(new UnauthorizedError("Invalid or expired access token"));
      return;
    }

    // Check PostgreSQL session truth so revoked sessions cannot keep using unexpired 15m JWTs
    const session = await prisma.session.findUnique({
      where: { id: payload.sid },
      select: {
        id: true,
        userId: true,
        revokedAt: true,
        expiresAt: true,
        user: {
          select: {
            id: true,
            status: true,
          },
        },
      },
    });

    if (!session || session.userId !== payload.sub) {
      next(new UnauthorizedError("Invalid session"));
      return;
    }

    if (session.revokedAt !== null) {
      next(new UnauthorizedError("Session has been revoked"));
      return;
    }

    if (session.expiresAt <= new Date()) {
      next(new UnauthorizedError("Session has expired"));
      return;
    }

    if (session.user.status === "CLOSED") {
      next(new ForbiddenError("This account has been closed. Please contact support."));
      return;
    }

    if (session.user.status === "PENDING_VERIFICATION") {
      next(new ForbiddenError("Please verify your email address before accessing this resource."));
      return;
    }

    // SUSPENDED accounts are permitted to authenticate for read-only account views
    req.auth = {
      userId: session.user.id,
      sessionId: session.id,
      status: session.user.status,
    };

    next();
  } catch (error) {
    next(error);
  }
}