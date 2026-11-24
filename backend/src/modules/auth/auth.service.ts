import argon2 from "argon2";
import { Prisma } from "@prisma/client";
import prisma from "../../config/prisma.js";
import {
  generateAccessToken,
  generateRefreshToken,
  hashRefreshToken,
} from "../../common/utils/token.js";
import { ConflictError, UnauthorizedError, ForbiddenError } from "../../utils/errors.js";
import type {
  RegisterInput,
  LoginInput,
  RefreshInput,
  UserResponse,
  LoginResult,
} from "./auth.types.js";

const DUMMY_ARGON2_HASH =
  "$argon2id$v=19$m=19456,t=2,p=1$kOWqRCgAgB0u44xSDeSuuQ$9s5WDmNfs2zV9VJvJG3obm53nAM/S+k3irOi0+sCG6s";

const REFRESH_TOKEN_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

export class AuthService {
  async register(input: RegisterInput): Promise<UserResponse> {
    const email = input.email.trim().toLowerCase();
    const { password, username } = input;

    const existingEmail = await prisma.user.findUnique({
      where: { email },
      select: { id: true },
    });

    if (existingEmail) {
      throw new ConflictError("An account with this email already exists");
    }

    if (username) {
      const existingUsername = await prisma.user.findUnique({
        where: { username },
        select: { id: true },
      });

      if (existingUsername) {
        throw new ConflictError("Username is already taken");
      }
    }

    const passwordHash = await argon2.hash(password, {
      type: argon2.argon2id,
      memoryCost: 19456, // 19 MB (OWASP recommended minimum to avoid OOM under load)
      timeCost: 2,
      parallelism: 1,
    });

    try {
      const user = await prisma.user.create({
        data: {
          email,
          passwordHash,
          username: username || null,
          status: "PENDING_VERIFICATION",
        },
        select: {
          id: true,
          email: true,
          username: true,
          status: true,
          createdAt: true,
        },
      });

      return user;
    } catch (error) {
      if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === "P2002") {
        const target = (error.meta?.target as string[]) || [];
        if (target.includes("email")) {
          throw new ConflictError("An account with this email already exists");
        }
        if (target.includes("username")) {
          throw new ConflictError("Username is already taken");
        }
        throw new ConflictError("An account with the provided details already exists");
      }
      throw error;
    }
  }

  async login(input: LoginInput): Promise<LoginResult> {
    const email = input.email.trim().toLowerCase();
    const { password, userAgent, ipAddress } = input;

    const user = await prisma.user.findUnique({
      where: { email },
      select: {
        id: true,
        email: true,
        username: true,
        passwordHash: true,
        status: true,
        createdAt: true,
      },
    });

    const hashToVerify = user?.passwordHash ?? DUMMY_ARGON2_HASH;
    const isPasswordValid = await argon2.verify(hashToVerify, password);

    if (!user || !isPasswordValid) {
      throw new UnauthorizedError("Invalid email or password");
    }

    if (user.status === "CLOSED") {
      throw new ForbiddenError("This account has been closed. Please contact support.");
    }

    if (user.status === "PENDING_VERIFICATION") {
      throw new ForbiddenError("Please verify your email address before logging in.");
    }

    const refreshToken = generateRefreshToken();
    const tokenHash = hashRefreshToken(refreshToken);
    const expiresAt = new Date(Date.now() + REFRESH_TOKEN_TTL_MS);

    const [, session] = await prisma.$transaction([
      prisma.user.update({
        where: { id: user.id },
        data: { lastLoginAt: new Date() },
      }),
      prisma.session.create({
        data: {
          userId: user.id,
          tokenHash,
          expiresAt,
          userAgent: userAgent ?? null,
          ipAddress: ipAddress ?? null,
        },
        select: { id: true },
      }),
    ]);

    const accessToken = await generateAccessToken({
      userId: user.id,
      sessionId: session.id,
    });

    return {
      user: {
        id: user.id,
        email: user.email,
        username: user.username,
        status: user.status,
        createdAt: user.createdAt,
      },
      tokens: {
        accessToken,
        refreshToken,
      },
    };
  }

  /**
   * Rotates a valid refresh token and detects reuse of already-rotated tokens.
   */
  async refresh(input: RefreshInput): Promise<LoginResult> {
    const { refreshToken, userAgent, ipAddress } = input;
    const tokenHash = hashRefreshToken(refreshToken);
    const now = new Date();

    const existingSession = await prisma.session.findUnique({
      where: { tokenHash },
      include: {
        user: {
          select: {
            id: true,
            email: true,
            username: true,
            status: true,
            createdAt: true,
          },
        },
      },
    });

    if (!existingSession) {
      throw new UnauthorizedError("Invalid refresh token");
    }

    // Reuse detection: token was already rotated or explicitly revoked
    if (existingSession.revokedAt !== null) {
      if (existingSession.replacedById !== null) {
        // Compromised chain: revoke every active session in this family
        await prisma.session.updateMany({
          where: {
            familyId: existingSession.familyId,
            revokedAt: null,
          },
          data: { revokedAt: now },
        });
        throw new UnauthorizedError("Refresh token reuse detected. Please log in again.");
      }

      throw new UnauthorizedError("Session has been revoked. Please log in again.");
    }

    if (existingSession.expiresAt <= now) {
      await prisma.session.updateMany({
        where: { id: existingSession.id, revokedAt: null },
        data: { revokedAt: now },
      });
      throw new UnauthorizedError("Refresh token expired. Please log in again.");
    }

    if (existingSession.user.status === "CLOSED") {
      await prisma.session.updateMany({
        where: { familyId: existingSession.familyId, revokedAt: null },
        data: { revokedAt: now },
      });
      throw new ForbiddenError("This account has been closed. Please contact support.");
    }

    if (existingSession.user.status === "PENDING_VERIFICATION") {
      throw new ForbiddenError("Please verify your email address before continuing.");
    }

    const newRefreshToken = generateRefreshToken();
    const newTokenHash = hashRefreshToken(newRefreshToken);
    const newExpiresAt = new Date(Date.now() + REFRESH_TOKEN_TTL_MS);

    // Atomic rotation: ensure only one concurrent request can claim and rotate this token
    const rotationResult = await prisma.$transaction(async (tx) => {
      const claim = await tx.session.updateMany({
        where: {
          id: existingSession.id,
          revokedAt: null,
        },
        data: {
          revokedAt: now,
          lastUsedAt: now,
        },
      });

      if (claim.count === 0) {
        return { rotated: false as const };
      }

      const nextSession = await tx.session.create({
        data: {
          userId: existingSession.user.id,
          tokenHash: newTokenHash,
          familyId: existingSession.familyId,
          expiresAt: newExpiresAt,
          userAgent: userAgent ?? null,
          ipAddress: ipAddress ?? null,
        },
        select: { id: true },
      });

      await tx.session.update({
        where: { id: existingSession.id },
        data: { replacedById: nextSession.id },
      });

      return { rotated: true as const, sessionId: nextSession.id };
    });

    // If a concurrent request just rotated this token, commit family revocation outside tx and reject
    if (!rotationResult.rotated) {
      await prisma.session.updateMany({
        where: {
          familyId: existingSession.familyId,
          revokedAt: null,
        },
        data: { revokedAt: now },
      });
      throw new UnauthorizedError("Refresh token reuse detected. Please log in again.");
    }

    const accessToken = await generateAccessToken({
      userId: existingSession.user.id,
      sessionId: rotationResult.sessionId,
    });

    return {
      user: existingSession.user,
      tokens: {
        accessToken,
        refreshToken: newRefreshToken,
      },
    };
  }

  /**
   * Idempotently revokes the current session matching the given refresh token.
   */
  async logout(refreshToken: string): Promise<void> {
    const tokenHash = hashRefreshToken(refreshToken);

    await prisma.session.updateMany({
      where: {
        tokenHash,
        revokedAt: null,
      },
      data: {
        revokedAt: new Date(),
      },
    });
  }

  //  Returns sanitized profile for the authenticated user.

  async getMe(userId: string): Promise<UserResponse> {
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        email: true,
        username: true,
        status: true,
        createdAt: true,
      },
    });

    if (!user) {
      throw new UnauthorizedError("User not found");
    }

    return user;
  }
}

export const authService = new AuthService();
