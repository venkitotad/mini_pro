// middlewares/campus.check.js
export function campusCheck(req, res, next) {
  const ip =
    req.headers["x-forwarded-for"]?.split(",")[0]?.trim() ||
    req.socket?.remoteAddress ||
    "";

  const ipv4 = ip.replace("::ffff:", "");

  // DEVELOPMENT WHITELIST
  if (process.env.NODE_ENV === "development") {
    if (ipv4 === "127.0.0.1" || ipv4 === "::1") {
      return next();
    }
  }

  // Only allow 10.100.x.x on production/in campus
  if (!ipv4.startsWith("10.100.")) {
    return res.status(403).json({
      error: "Access restricted. Connect to BMSIT-Student WiFi.",
      yourIP: ipv4,
    });
  }

  next();
}
