import type { Request, Response, NextFunction } from "express";
import type { UserStatus } from "@prisma/client";
import type { } from "../types/express.js";
import { ForbiddenError, UnauthorizedError } from "../utils/errors.js";


export function authorize(...allowedStatuses: UserStatus[]) {
  return (req: Request, _res: Response, next: NextFunction): void => {
    if (!req.auth) {
      next(new UnauthorizedError("Authentication required"));
      return;
    }

    if (allowedStatuses.length > 0 && !allowedStatuses.includes(req.auth.status)) {
      next(new ForbiddenError("You do not have permission to perform this action"));
      return;
    }

    next();
  };
}
