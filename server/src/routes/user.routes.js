import express from "express";
import { requireAuth, clerkClient } from "@clerk/express";
import { pool } from "../config/db.js";

const router = express.Router();

router.post("/sync", requireAuth(), async (req, res) => {
  try {
    const { userId } = req.auth;
    const { role } = req.body;

    if (!role) return res.status(400).json({ error: "Role required" });

    const clerkUser = await clerkClient.users.getUser(userId);
    const email = clerkUser.emailAddresses?.[0]?.emailAddress || null;
    const fullName =
      `${clerkUser.firstName || ""} ${clerkUser.lastName || ""}`.trim() || null;

    const { rows } = await pool.query(
      `
      INSERT INTO users (clerk_user_id, email, role, full_name)
      VALUES ($1, $2, $3, $4)
      ON CONFLICT (clerk_user_id)
      DO UPDATE SET
        email = EXCLUDED.email,
        full_name = EXCLUDED.full_name,
        updated_at = NOW(),
        role = CASE WHEN users.role IS NULL THEN EXCLUDED.role ELSE users.role END
      RETURNING *;
      `,
      [userId, email, role, fullName]
    );

    console.log(`Synced user: ${email || "no-email"} (${rows[0].role})`);
    res.json({ user: rows[0] });
  } catch (err) {
    console.error("Error in /sync:", err);
    res.status(500).json({ error: "Internal Server Error" });
  }
});


router.get("/me", requireAuth(), async (req, res) => {
  const { userId } = req.auth;
  const { rows } = await pool.query("SELECT * FROM users WHERE clerk_user_id = $1", [userId]);
  if (!rows.length) return res.status(404).json({ error: "User not found" });
  res.json(rows[0]);
});

export default router;
