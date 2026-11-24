import { Router } from "express";
import { authController } from "./auth.controller.js";
import { authenticate } from "../../middlewares/authenticate.js";
import {
  registerRateLimiter,
  loginRateLimiter,
  refreshRateLimiter,
} from "../../middlewares/authRateLimiter.js";

const router = Router();

// Order: Rate limiter -> Validation (in controller) -> Service -> DB
router.post("/register", registerRateLimiter, (req, res, next) => {
  authController.register(req, res, next);
});

router.post("/login", loginRateLimiter, (req, res, next) => {
  authController.login(req, res, next);
});

router.post("/refresh", refreshRateLimiter, (req, res, next) => {
  authController.refresh(req, res, next);
});

router.post("/logout", (req, res, next) => {
  authController.logout(req, res, next);
});

router.get("/me", authenticate, (req, res, next) => {
  authController.me(req, res, next);
});

export default router;
