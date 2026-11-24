import rateLimit from "express-rate-limit";

export interface RateLimiterConfig {
  windowMs?: number;
  max?: number;
  message?: string;
}


export const createRateLimiter = (options?: RateLimiterConfig) => {
  return rateLimit({
    windowMs: options?.windowMs ?? 15 * 60 * 1000, // 15 minutes default
    limit: options?.max ?? 10,                     // 10 requests per IP default
    statusCode: 429,
    standardHeaders: "draft-7",                    // Return standard RateLimit-* headers (draft-7)
    legacyHeaders: false,                          // Disable X-RateLimit-* headers
    handler: (_req, res) => {
      res.status(429).json({
        success: false,
        message: options?.message ?? "Too many requests. Please try again later.",
      });
    },
  });
};


//  * Rate limiter for user registration (10 requests per 15 mins per IP).
export const registerRateLimiter = createRateLimiter({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: "Too many accounts created from this IP. Please try again after 15 minutes.",
});


//  * Rate limiter for user login

export const loginRateLimiter = createRateLimiter({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: "Too many login attempts from this IP. Please try again after 15 minutes.",
});


export const refreshRateLimiter = createRateLimiter({
  windowMs: 15 * 60 * 1000,
  max: 30,
  message: "Too many refresh attempts from this IP. Please try again later.",
});

export const authRateLimiter = registerRateLimiter;

export default authRateLimiter;
