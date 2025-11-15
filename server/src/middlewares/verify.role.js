import { requireAuth } from "@clerk/express";
import { pool } from "../config/db.js";

/**
 * Middleware to protect routes by user role.
 * Usage: router.get("/dashboard", requireRole("staff"), ...)
 */
export function requireRole(requiredRole) {
  return [
    requireAuth(), // Clerk auth validation
    async (req, res, next) => {
      try {
        const { userId: clerkUserId } = req.auth;

        // Fetch user record
        const { rows } = await pool.query(
          "SELECT id, role FROM users WHERE clerk_user_id = $1",
          [clerkUserId]
        );

        if (rows.length === 0) {
          return res.status(404).json({ error: "User not found in database" });
        }

        const dbUser = rows[0];

        // Attach user details
        req.userId = dbUser.id;     
        req.userRole = dbUser.role;

        // Check role
        if (dbUser.role !== requiredRole) {
          return res.status(403).json({
            error: `Access denied: requires '${requiredRole}' role`,
          });
        }

        next();
      } catch (err) {
        console.error("Role verification error:", err);
        return res.status(500).json({ error: "Internal Server Error" });
      }
    },
  ];
}
