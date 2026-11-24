import app from "./app.js";
import { connectDB } from "./config/prisma.js";

const port = process.env.PORT || 8080;

async function startServer() {
  await connectDB();

  app.listen(port, () => {
    console.log(`🚀 Server listening on port ${port}...`);
  });
}

startServer();
