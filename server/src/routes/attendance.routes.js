// import express from "express";
// import { requireRole } from "../middlewares/verify.role.js";
// import { pool } from "../config/db.js";

// const router = express.Router();

// /* -----------------------------------------
//    Vincenty Formula (more accurate than Haversine)
//    Returns distance in meters
// ----------------------------------------- */
// function calculateDistance(lat1, lon1, lat2, lon2) {
//   const toRad = (x) => (x * Math.PI) / 180;

//   const a = 6378137; // major semi-axis (WGS-84)
//   const f = 1 / 298.257223563;
//   const b = (1 - f) * a;

//   const φ1 = toRad(lat1);
//   const φ2 = toRad(lat2);
//   const L = toRad(lon2 - lon1);

//   let λ = L;
//   let λPrev;
//   let iter = 0;

//   const U1 = Math.atan((1 - f) * Math.tan(φ1));
//   const U2 = Math.atan((1 - f) * Math.tan(φ2));

//   const sinU1 = Math.sin(U1),
//     cosU1 = Math.cos(U1);
//   const sinU2 = Math.sin(U2),
//     cosU2 = Math.cos(U2);

//   let sinλ, cosλ, sinσ, cosσ, σ, sinα, cosSqα, cos2σm, C;

//   do {
//     iter++;
//     if (iter > 200) return NaN; // failsafe

//     sinλ = Math.sin(λ);
//     cosλ = Math.cos(λ);

//     sinσ = Math.sqrt(
//       (cosU2 * sinλ) ** 2 +
//         (cosU1 * sinU2 - sinU1 * cosU2 * cosλ) ** 2
//     );

//     if (sinσ === 0) return 0; // same coordinates

//     cosσ = sinU1 * sinU2 + cosU1 * cosU2 * cosλ;
//     σ = Math.atan2(sinσ, cosσ);

//     sinα = (cosU1 * cosU2 * sinλ) / sinσ;
//     cosSqα = 1 - sinα ** 2;

//     cos2σm = cosSqα !== 0 ? cosσ - (2 * sinU1 * sinU2) / cosSqα : 0;

//     C = (f / 16) * cosSqα * (4 + f * (4 - 3 * cosSqα));

//     λPrev = λ;
//     λ =
//       L +
//       (1 - C) *
//         f *
//         sinα *
//         (σ +
//           C *
//             sinσ *
//             (cos2σm +
//               C * cosσ * (-1 + 2 * cos2σm ** 2)));
//   } while (Math.abs(λ - λPrev) > 1e-12);

//   const uSq = (cosSqα * (a ** 2 - b ** 2)) / (b ** 2);
//   const A =
//     1 +
//     (uSq / 16384) *
//       (4096 + uSq * (-768 + uSq * (320 - 175 * uSq)));
//   const B =
//     (uSq / 1024) *
//     (256 + uSq * (-128 + uSq * (74 - 47 * uSq)));

//   const Δσ =
//     B *
//     sinσ *
//     (cos2σm +
//       (B / 4) *
//         (cosσ * (-1 + 2 * cos2σm ** 2) -
//           (B / 6) * cos2σm * (-3 + 4 * sinσ ** 2) * (-3 + 4 * cos2σm ** 2)));

//   return b * A * (σ - Δσ); // distance in meters
// }

// /* -----------------------------------------
//    Mark attendance
// ----------------------------------------- */
// router.post("/mark", requireRole("student"), async (req, res) => {
//   try {
//     const { sessionId, lat, lng } = req.body;

//     if (!sessionId || !lat || !lng) {
//       return res.status(400).json({ error: "sessionId, lat, lng required" });
//     }

//     // 1) Student info
//     const studentRes = await pool.query(
//       `SELECT id, class_id FROM students WHERE user_id = $1`,
//       [req.userId]
//     );

//     if (studentRes.rows.length === 0) {
//       return res.status(404).json({ error: "Student not found" });
//     }

//     const student = studentRes.rows[0];

//     // 2) Validate session
//     const sessionRes = await pool.query(
//       `
//       SELECT *
//       FROM attendance_sessions
//       WHERE id = $1
//       AND expires_at > NOW()
//       `,
//       [sessionId]
//     );

//     if (sessionRes.rows.length === 0) {
//       return res.status(400).json({ error: "Session expired or invalid" });
//     }

//     const session = sessionRes.rows[0];

//     // 3) Check class match
//     if (student.class_id !== session.class_id) {
//       return res.status(403).json({ error: "You don't belong to this class" });
//     }

//     // 4) Get classroom geofence
//     const classRes = await pool.query(
//       `SELECT latitude, longitude, radius FROM classes WHERE id = $1`,
//       [session.class_id]
//     );

//     const classRoom = classRes.rows[0];

//     // 5) Distance calculation
//     const distance = calculateDistance(
//       Number(lat),
//       Number(lng),
//       Number(classRoom.latitude),
//       Number(classRoom.longitude)
//     );

//     console.log("Geofence Distance:", distance, "allowed:", classRoom.radius);

//     if (isNaN(distance)) {
//       return res.status(500).json({ error: "Distance calculation failed" });
//     }

//     if (distance > classRoom.radius) {
//       return res.status(403).json({
//         error: "You are outside the classroom boundary",
//         distance,
//         allowed: classRoom.radius,
//       });
//     }

//     // 6) Prevent duplicate attendance
//     await pool.query(
//       `
//       INSERT INTO attendance_records (session_id, student_id, status)
//       VALUES ($1, $2, 'present')
//       ON CONFLICT (session_id, student_id)
//       DO NOTHING
//       `,
//       [sessionId, student.id]
//     );

//     res.json({
//       success: true,
//       message: "Attendance marked successfully",
//     });
//   } catch (err) {
//     console.error("Attendance error:", err);
//     res.status(500).json({ error: "Internal server error" });
//   }
// });

// export default router;

import express from "express";
import { requireRole } from "../middlewares/verify.role.js";
import { pool } from "../config/db.js";

const router = express.Router();

/* -----------------------------------------
   Ultra-Precise Vincenty Formula
----------------------------------------- */
function calculateDistance(lat1, lon1, lat2, lon2) {
  const toRad = (x) => (x * Math.PI) / 180;

  const a = 6378137;
  const f = 1 / 298.257223563;
  const b = (1 - f) * a;

  const φ1 = toRad(lat1);
  const φ2 = toRad(lat2);
  const L = toRad(lon2 - lon1);

  let λ = L;
  let λPrev;
  let iter = 0;

  const U1 = Math.atan((1 - f) * Math.tan(φ1));
  const U2 = Math.atan((1 - f) * Math.tan(φ2));

  const sinU1 = Math.sin(U1),
    cosU1 = Math.cos(U1);
  const sinU2 = Math.sin(U2),
    cosU2 = Math.cos(U2);

  let sinλ, cosλ, sinσ, cosσ, σ, sinα, cosSqα, cos2σm, C;

  do {
    iter++;
    if (iter > 200) return NaN;

    sinλ = Math.sin(λ);
    cosλ = Math.cos(λ);

    sinσ = Math.sqrt(
      (cosU2 * sinλ) ** 2 +
        (cosU1 * sinU2 - sinU1 * cosU2 * cosλ) ** 2
    );

    if (sinσ === 0) return 0;

    cosσ = sinU1 * sinU2 + cosU1 * cosU2 * cosλ;
    σ = Math.atan2(sinσ, cosσ);

    sinα = (cosU1 * cosU2 * sinλ) / sinσ;
    cosSqα = 1 - sinα ** 2;

    cos2σm = cosSqα !== 0 ? cosσ - (2 * sinU1 * sinU2) / cosSqα : 0;

    C = (f / 16) * cosSqα * (4 + f * (4 - 3 * cosSqα));

    λPrev = λ;
    λ =
      L +
      (1 - C) *
        f *
        sinα *
        (σ +
          C *
            sinσ *
            (cos2σm +
              C * cosσ * (-1 + 2 * cos2σm ** 2)));
  } while (Math.abs(λ - λPrev) > 1e-13); // tighter accuracy

  const uSq = (cosSqα * (a ** 2 - b ** 2)) / (b ** 2);
  const A =
    1 +
    (uSq / 16384) *
      (4096 + uSq * (-768 + uSq * (320 - 175 * uSq)));
  const B =
    (uSq / 1024) *
    (256 + uSq * (-128 + uSq * (74 - 47 * uSq)));

  const Δσ =
    B *
    sinσ *
    (cos2σm +
      (B / 4) *
        (cosσ * (-1 + 2 * cos2σm ** 2) -
          (B / 6) *
            cos2σm *
            (-3 + 4 * sinσ ** 2) *
            (-3 + 4 * cos2σm ** 2)));

  return b * A * (σ - Δσ);
}

/* -----------------------------------------
   Mark Attendance (Ultra Accurate Version)
----------------------------------------- */
router.post("/mark", requireRole("student"), async (req, res) => {
  try {
    const { sessionId, lat1, lng1, lat2, lng2 } = req.body;

    // Require double GPS readings
    if (!sessionId || !lat1 || !lng1 || !lat2 || !lng2) {
      return res.status(400).json({ error: "Need sessionId + 2 GPS readings" });
    }

    // Reject impossible GPS
    if (lat1 === 0 || lng1 === 0 || lat2 === 0 || lng2 === 0) {
      return res.status(400).json({ error: "Invalid GPS coordinate" });
    }

    // Weighted average (smooth)
    const lat = (Number(lat1) + Number(lat2)) / 2;
    const lng = (Number(lng1) + Number(lng2)) / 2;

    // Student info
    const studentRes = await pool.query(
      `SELECT id, class_id FROM students WHERE user_id = $1`,
      [req.userId]
    );

    if (studentRes.rows.length === 0) {
      return res.status(404).json({ error: "Student not found" });
    }

    const student = studentRes.rows[0];

    // Validate session
    const sessionRes = await pool.query(
      `SELECT * FROM attendance_sessions
       WHERE id = $1 AND expires_at > NOW()`,
      [sessionId]
    );

    if (sessionRes.rows.length === 0) {
      return res.status(400).json({ error: "Session expired or invalid" });
    }

    const session = sessionRes.rows[0];

    // Class match
    if (student.class_id !== session.class_id) {
      return res.status(403).json({ error: "You don't belong to this class" });
    }

    // Get classroom geofence
    const classRes = await pool.query(
      `SELECT latitude, longitude, radius FROM classes WHERE id = $1`,
      [session.class_id]
    );

    const room = classRes.rows[0];

    // Distance calculation
    const distance = calculateDistance(
      lat,
      lng,
      Number(room.latitude),
      Number(room.longitude)
    );

    console.log("Distance:", distance, "allowed:", room.radius);

    if (distance > room.radius) {
      return res.status(403).json({
        error: "You are outside classroom boundary",
        distance,
        allowed: room.radius,
      });
    }

    // Insert attendance
    await pool.query(
      `INSERT INTO attendance_records (session_id, student_id, status)
       VALUES ($1, $2, 'present')
       ON CONFLICT (session_id, student_id) DO NOTHING`,
      [sessionId, student.id]
    );

    res.json({ success: true, message: "Attendance marked" });
  } catch (err) {
    console.error("Attendance error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

export default router;
