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

    // Insert / update USERS table
    const { rows } = await pool.query(
      `
      INSERT INTO users (clerk_user_id, email, role, full_name)
      VALUES ($1, $2, $3, $4)
      ON CONFLICT (clerk_user_id)
      DO UPDATE SET
        email = EXCLUDED.email,
        full_name = EXCLUDED.full_name,
        updated_at = NOW(),
        role = CASE 
                 WHEN users.role IS NULL THEN EXCLUDED.role 
                 ELSE users.role 
               END
      RETURNING *;
      `,
      [userId, email, role, fullName]
    );

    const appUser = rows[0];

    // Auto-create student row
    if (role === "student") {
      await pool.query(
        `
        INSERT INTO students (user_id)
        VALUES ($1)
        ON CONFLICT (user_id) DO NOTHING;
        `,
        [appUser.id]
      );
      console.log(`Student synced: ${email}`);
    }

    // 🔥 CRITICAL FIX — Store role in Clerk publicMetadata
    await clerkClient.users.updateUser(userId, {
      publicMetadata: {
        role: appUser.role,
      },
    });

    console.log(`Synced user: ${email || "no-email"} (${appUser.role})`);

    res.json({ user: appUser });

  } catch (err) {
    console.error("Error in /sync:", err);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

router.get("/me", requireAuth(), async (req, res) => {
  const { userId } = req.auth;
  const { rows } = await pool.query(
    "SELECT * FROM users WHERE clerk_user_id = $1",
    [userId]
  );
  if (!rows.length) return res.status(404).json({ error: "User not found" });
  res.json(rows[0]);
});

export default router;
