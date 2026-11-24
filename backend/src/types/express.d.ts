import type { UserStatus } from "@prisma/client";

export interface AuthContext {
  userId: string;
  sessionId: string;
  status: UserStatus;
}

declare global {
  namespace Express {
    interface Request {
      auth?: AuthContext;
    }
  }
}

