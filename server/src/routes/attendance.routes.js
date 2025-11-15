import express from "express";
import { requireRole } from "../middlewares/verify.role.js";
import { pool } from "../config/db.js";

const router = express.Router();

// Haversine formula for distance calc
function calculateDistance(lat1, lon1, lat2, lon2) {
  const R = 6371e3; // meters
  const toRad = (x) => (x * Math.PI) / 180;

  const φ1 = toRad(lat1);
  const φ2 = toRad(lat2);
  const Δφ = toRad(lat2 - lat1);
  const Δλ = toRad(lon2 - lon1);

  const a =
    Math.sin(Δφ / 2) ** 2 +
    Math.cos(φ1) * Math.cos(φ2) * Math.sin(Δλ / 2) ** 2;

  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));

  return R * c;
}

//marking attedance
router.post("/mark", requireRole("student"), async (req, res) => {
  try {
    const { sessionId, lat, lng } = req.body;

    if (!sessionId || !lat || !lng) {
      return res.status(400).json({ error: "sessionId, lat, lng required" });
    }

    // 1) Fetch student record
    const studentRes = await pool.query(
      "SELECT id, class_id FROM students WHERE user_id = $1",
      [req.userId]
    );

    if (studentRes.rows.length === 0) {
      return res.status(404).json({ error: "Student not found" });
    }

    const student = studentRes.rows[0];

    // Validate active session
    const sessionRes = await pool.query(
      `
      SELECT *
      FROM attendance_sessions
      WHERE id = $1
      AND expires_at > NOW()
      `,
      [sessionId]
    );

    if (sessionRes.rows.length === 0) {
      return res.status(400).json({ error: "Session expired or invalid" });
    }

    const session = sessionRes.rows[0];

    //  Check student belongs to the session’s class
    if (student.class_id !== session.class_id) {
      return res.status(403).json({ error: "You don't belong to this class" });
    }

    // Get class geofence info
    const classRes = await pool.query(
      `
      SELECT latitude, longitude, radius
      FROM classes
      WHERE id = $1
      `,
      [session.class_id]
    );

    const classRoom = classRes.rows[0];

    // Calculate distance
   const distance = calculateDistance(
  Number(lat),
  Number(lng),
  Number(classRoom.latitude),
  Number(classRoom.longitude)
);


    console.log("Geofence distance:", distance, "allowed:", classRoom.radius);

    if (distance > classRoom.radius) {
      return res.status(403).json({
        error: "You are not inside the classroom boundary",
        distance,
        allowed: classRoom.radius,
      });
    }

    // Prevent duplicate attendance
    await pool.query(
      `
      INSERT INTO attendance_records (session_id, student_id, status)
      VALUES ($1, $2, 'present')
      ON CONFLICT (session_id, student_id)
      DO NOTHING
      `,
      [sessionId, student.id]
    );

    return res.json({
      success: true,
      message: "Attendance marked successfully",
    });
  } catch (err) {
    console.error("Attendance error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

export default router;
