import express from "express";
import { requireRole } from "./../middlewares/verify.role.js";


const router = express.Router();

router.get("/dashboard", requireRole("student"), async (req, res) => {
  res.json({
    message: "🎓 Student Dashboard working",
    role: req.userRole,
  });
});

export default router;
