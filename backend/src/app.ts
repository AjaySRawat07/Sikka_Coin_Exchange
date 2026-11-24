import express, { type Request, type Response, type NextFunction } from "express";
import cookieParser from "cookie-parser";
import prisma from "./config/prisma.js";
import authRoutes from "./modules/auth/auth.routes.js";
import { AppError } from "./utils/errors.js";

const app = express();

app.set("trust proxy", 1);

app.use(express.json());
app.use(cookieParser());


app.use("/api/auth", authRoutes);

app.get("/health", async (_req: Request, res: Response) => {
    try {
        await prisma.$queryRaw`SELECT 1`;
        res.status(200).json({ status: "healthy", database: "connected" });
    } catch (error) {
        console.error("Health check error:", error);
        res.status(503).json({ status: "unhealthy", database: "disconnected" });
    }
});

app.get("/", (_req: Request, res: Response) => {
    res.send("Sikka Exchange API is running");
});


app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
  if (err instanceof AppError) {
    res.status(err.statusCode).json({
      success: false,
      message: err.message,
    });
    return;
  }

  console.error("Unhandled Server Error:", err);
  res.status(500).json({
    success: false,
    message: "Internal server error",
  });
});

export default app;

