import { type UserStatus } from "@prisma/client";

export interface RegisterInput {
  email: string;
  password: string;
  username?: string;
}

export interface LoginInput {
  email: string;
  password: string;
  userAgent?: string;
  ipAddress?: string;
}

export interface RefreshInput {
  refreshToken: string;
  userAgent?: string;
  ipAddress?: string;
}

export interface UserResponse {
  id: string;
  email: string;
  username: string | null;
  status: UserStatus;
  createdAt: Date;
}

export interface TokenPair {
  accessToken: string;
  refreshToken: string;
}

export interface LoginResult {
  user: UserResponse;
  tokens: TokenPair;
}

export interface AuthSuccessResponse {
  success: true;
  message: string;
  data: {
    user: UserResponse;
    accessToken?: string;
  };
}

export interface AuthErrorResponse {
  success: false;
  message: string;
  errors?: Record<string, string[]>;
}
