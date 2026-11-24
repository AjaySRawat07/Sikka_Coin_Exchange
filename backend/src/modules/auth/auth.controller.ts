import type { Request, Response, NextFunction } from "express";
import type { } from "../../types/express.js";
import { authService } from "./auth.service.js";
import { registerSchema, loginSchema } from "./auth.validation.js";
import {
  REFRESH_TOKEN_COOKIE_NAME,
  setRefreshTokenCookie,
  clearRefreshTokenCookie,
} from "../../common/utils/cookies.js";
import { AppError, UnauthorizedError, ForbiddenError } from "../../utils/errors.js";

export class AuthController {
  // Handles POST /api/auth/register

  async register(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const parseResult = registerSchema.safeParse(req.body);

      if (!parseResult.success) {
        const validationErrors: Record<string, string[]> = {};
        for (const issue of parseResult.error.issues) {
          const field = issue.path.join(".") || "body";
          if (!validationErrors[field]) {
            validationErrors[field] = [];
          }
          validationErrors[field].push(issue.message);
        }

        res.status(400).json({
          success: false,
          message: "Validation failed",
          errors: validationErrors,
        });
        return;
      }

      const user = await authService.register(parseResult.data);

      res.status(201).json({
        success: true,
        message: "User registered successfully. Please verify your email.",
        data: {
          user,
        },
      });
    } catch (error) {
      if (error instanceof AppError) {
        res.status(error.statusCode).json({
          success: false,
          message: error.message,
        });
        return;
      }

      next(error);
    }
  }

  // Handles POST /api/auth/login

  async login(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const parseResult = loginSchema.safeParse(req.body);

      if (!parseResult.success) {
        const validationErrors: Record<string, string[]> = {};
        for (const issue of parseResult.error.issues) {
          const field = issue.path.join(".") || "body";
          if (!validationErrors[field]) {
            validationErrors[field] = [];
          }
          validationErrors[field].push(issue.message);
        }

        res.status(400).json({
          success: false,
          message: "Validation failed",
          errors: validationErrors,
        });
        return;
      }

      const result = await authService.login({
        ...parseResult.data,
        userAgent: req.get("user-agent"),
        ipAddress: req.ip,
      });

      setRefreshTokenCookie(res, result.tokens.refreshToken);

      res.status(200).json({
        success: true,
        message: "Login successful",
        data: {
          user: result.user,
          accessToken: result.tokens.accessToken,
        },
      });
    } catch (error) {
      if (error instanceof AppError) {
        res.status(error.statusCode).json({
          success: false,
          message: error.message,
        });
        return;
      }

      next(error);
    }
  }

  // Handles POST /api/auth/refresh

  async refresh(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const refreshToken = req.cookies?.[REFRESH_TOKEN_COOKIE_NAME];

      if (typeof refreshToken !== "string" || refreshToken.length === 0) {
        throw new UnauthorizedError("Refresh token is missing");
      }

      const result = await authService.refresh({
        refreshToken,
        userAgent: req.get("user-agent"),
        ipAddress: req.ip,
      });

      setRefreshTokenCookie(res, result.tokens.refreshToken);

      res.status(200).json({
        success: true,
        message: "Token refreshed successfully",
        data: {
          user: result.user,
          accessToken: result.tokens.accessToken,
        },
      });
    } catch (error) {
      if (error instanceof UnauthorizedError || error instanceof ForbiddenError) {
        clearRefreshTokenCookie(res);
      }

      if (error instanceof AppError) {
        res.status(error.statusCode).json({
          success: false,
          message: error.message,
        });
        return;
      }

      next(error);
    }
  }

  // Handles POST /api/auth/logout

  async logout(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const refreshToken = req.cookies?.[REFRESH_TOKEN_COOKIE_NAME];

      if (typeof refreshToken === "string" && refreshToken.length > 0) {
        await authService.logout(refreshToken);
      }

      clearRefreshTokenCookie(res);

      res.status(200).json({
        success: true,
        message: "Logged out successfully",
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Handles GET /api/auth/me
   */
  async me(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      if (!req.auth) {
        throw new UnauthorizedError("Authentication required");
      }

      const user = await authService.getMe(req.auth.userId);

      res.status(200).json({
        success: true,
        data: {
          user,
        },
      });
    } catch (error) {
      if (error instanceof AppError) {
        res.status(error.statusCode).json({
          success: false,
          message: error.message,
        });
        return;
      }

      next(error);
    }
  }
}

export const authController = new AuthController();
