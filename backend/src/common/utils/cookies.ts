import type { CookieOptions, Response } from "express";

export const REFRESH_TOKEN_COOKIE_NAME = "refresh_token";
const REFRESH_TOKEN_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000;

function getBaseCookieOptions(): CookieOptions {
  return {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    path: "/api/auth",
  };
}

export function setRefreshTokenCookie(res: Response, token: string): void {
  res.cookie(REFRESH_TOKEN_COOKIE_NAME, token, {
    ...getBaseCookieOptions(),
    maxAge: REFRESH_TOKEN_MAX_AGE_MS,
  });
}

export function clearRefreshTokenCookie(res: Response): void {
  res.clearCookie(REFRESH_TOKEN_COOKIE_NAME, getBaseCookieOptions());
}

