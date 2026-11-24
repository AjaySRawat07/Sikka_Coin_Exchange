import type { Request, Response, NextFunction } from "express";
import type {} from "../types/express.js";
import { ForbiddenError, UnauthorizedError } from "../utils/errors.js";

/**
 * Fail-closed trading guard: blocks SUSPENDED, CLOSED, and PENDING_VERIFICATION accounts
 * from placing/canceling orders or performing financial mutations.
 */
export function requireTradingAccess(req: Request, _res: Response, next: NextFunction): void {
  if (!req.auth) {
    next(new UnauthorizedError("Authentication required"));
    return;
  }

  if (req.auth.status === "SUSPENDED") {
    next(new ForbiddenError("Your account is suspended. Trading and withdrawals are restricted."));
    return;
  }

  if (req.auth.status !== "ACTIVE") {
    next(new ForbiddenError("Account is not eligible for trading."));
    return;
  }

  next();
}
