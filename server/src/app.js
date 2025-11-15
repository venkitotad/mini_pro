// src/app.js
import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import morgan from "morgan";
import dotenv from "dotenv";
import bodyParser from "body-parser";
import { pool } from "./config/db.js";
import userRouter from "./routes/user.routes.js";
import { clerkMiddleware } from "@clerk/express";
// import dashboardRouter from "./routes/student.routes.js";
import studentRouter from "./routes/student.routes.js";
import staffRouter from "./routes/staff.routes.js";
import attendanceRouter from "./routes/attendance.routes.js";

dotenv.config();
const app = express();

// Middleware
app.use(morgan("dev"));
app.use(express.json());
app.use(cookieParser());
app.use(bodyParser.json());

// ✅ Enable Clerk middleware globally (must come before your routes)
app.use(clerkMiddleware());

// CORS
app.use(
  cors({
    origin: "http://localhost:5173",
    credentials: true,
  })
);

app.use((req, res, next) => {
  res.setHeader("Permissions-Policy", "geolocation=(self)");
  next();
});



// Health check
app.get("/health", async (req, res) => {
  try {
    const result = await pool.query("SELECT NOW()");
    res.json({ status: "ok", time: result.rows[0].now });
  } catch (err) {
    console.error(err);
    res.status(500).json({ status: "error" });
  }
});

// Routes
app.use("/api/users", userRouter);
app.use("/api/student", studentRouter);
app.use("/api/staff", staffRouter);
app.use("/api/attendance", attendanceRouter);



export default app;
