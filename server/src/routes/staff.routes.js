import express from "express";
import { requireRole } from "./../middlewares/verify.role.js";

const router = express.Router();

router.get("/dashboard", requireRole("staff"), async (req, res) => {
  res.json({
    message: "👨‍🏫 Staff Dashboard working",
    role: req.userRole,
  });
});

export default router;
