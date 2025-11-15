import express from "express";
import { requireRole } from "./../middlewares/verify.role.js";
import { pool } from "../config/db.js";


const router = express.Router();

router.get("/dashboard", requireRole("student"), async (req, res) => {
  try {
  
    const student = await pool.query(
      "SELECT id, class_id FROM students WHERE user_id = $1",
      [req.userId]
    );

    if (student.rows.length === 0) {
      return res.status(404).json({ error: "Student record not found" });
    }

    const studentRow = student.rows[0];

    // 2. Fetch class info
    const classInfo = await pool.query(
      "SELECT id, name, subject FROM classes WHERE id = $1",
      [studentRow.class_id]
    );

    res.json({
      role: "student",
      student_id: studentRow.id,
      class: classInfo.rows[0] || null
    });

  } catch (err) {
    console.error("Student dashboard error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});



//ACTIVE SESSION FOR STUDENT 
router.get("/active-session", requireRole("student"), async (req, res) => {
  try {
    const userId = req.userId;

    const result = await pool.query(
      `
      SELECT s.id, s.class_id, s.expires_at, s.session_code, c.name, c.subject
      FROM attendance_sessions s
      JOIN students st ON st.class_id = s.class_id
      JOIN classes c ON c.id = s.class_id
      WHERE st.user_id = $1
      AND s.expires_at > NOW()
      ORDER BY s.id DESC
      LIMIT 1
      `,
      [userId]
    );

    res.json({
      session: result.rows[0] || null,
    });

  } catch (err) {
    console.error("Active session error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

export default router;
