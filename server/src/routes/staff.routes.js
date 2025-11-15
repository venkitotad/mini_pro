import express from "express";
import { requireRole } from "./../middlewares/verify.role.js";
import { pool } from "../config/db.js";
import crypto from "crypto"; 
const router = express.Router();

router.get("/dashboard", requireRole("staff"), async (req, res) => {
  try {
    //Fetch staff info from DB
    const staff = await pool.query(
      "SELECT id, full_name, email FROM users WHERE id = $1 AND role = 'staff'",
      [req.userId]
    );

    if (staff.rows.length === 0) {
      return res.status(403).json({ error: "Staff not found." });
    }

    //Get classes owned by the staff
    const classes = await pool.query(
      "SELECT id, name, subject FROM classes WHERE staff_id = $1",
      [req.userId]
    );

    // Return dashboard response
    res.json({
      role: "staff",
      name: staff.rows[0].full_name,
      email: staff.rows[0].email,
      classes: classes.rows,
    });

  } catch (err) {
    console.error("Dashboard error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});


router.post("/start-session", requireRole("staff"), async (req, res) => {
  try {
    const { classId } = req.body;

    if (!classId) {
      return res.status(400).json({ error: "classId is required" });
    }

    // Check  class belongs to this staff member
    const checkClass = await pool.query(
      "SELECT id FROM classes WHERE id = $1 AND staff_id = $2",
      [classId, req.userId]
    );

    if (checkClass.rows.length === 0) {
      return res.status(403).json({
        error: "You are not assigned to this class",
      });
    }

    //  Generate session code
    const sessionCode = crypto.randomBytes(3).toString("hex");

    //  Create attendance session
    const newSession = await pool.query(
      `
      INSERT INTO attendance_sessions (class_id, session_code)
      VALUES ($1, $2)
      RETURNING id, class_id, session_code, expires_at
      `,
      [classId, sessionCode]
    );

    res.json({
      success: true,
      session: newSession.rows[0],
    });

  } catch (err) {
    console.error("Start session error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});


export default router;
