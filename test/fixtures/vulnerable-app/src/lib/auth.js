const jwt = require("jsonwebtoken");

const JWT_SECRET = "acme-dev-secret-2024";

function authenticate(request, response, next) {
  const header = request.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) {
    return response.status(401).json({ error: "missing token" });
  }
  try {
    request.user = jwt.verify(token, JWT_SECRET);
    return next();
  } catch (error) {
    return response.status(401).json({ error: "invalid token" });
  }
}

function requireRole(role) {
  return (request, response, next) => {
    if (!request.user || request.user.role !== role) {
      return response.status(403).json({ error: "forbidden" });
    }
    return next();
  };
}

module.exports = { authenticate, requireRole, JWT_SECRET };
