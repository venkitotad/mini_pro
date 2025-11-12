import { requireAuth } from "@clerk/express";
import { pool } from "../config/db.js";

/**
 * Middleware to protect routes by user role.
 * Usage: router.get("/dashboard", requireRole("staff"), ...)
 */
export function requireRole(requiredRole) {
  return [
    requireAuth(), // Ensures the user is authenticated with Clerk
    async (req, res, next) => {
      try {
        const { userId } = req.auth;

        // Fetch user record from your PostgreSQL
        const { rows } = await pool.query(
          "SELECT role FROM users WHERE clerk_user_id = $1",
          [userId]
        );

        if (rows.length === 0) {
          return res.status(404).json({ error: "User not found in database" });
        }

        const userRole = rows[0].role;

        // Attach to request for downstream usage
        req.userRole = userRole;

        // Check if user has the required role
        if (userRole !== requiredRole) {
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
