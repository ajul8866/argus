const express = require("express");
const { searchUsers, findUserById } = require("../lib/db");
const { requireRole } = require("../lib/auth");

const router = express.Router();

// Directory search is available to every authenticated user.
router.get("/search", (request, response) => {
  const term = String(request.query.q || "");
  const results = searchUsers(term);
  response.json({ results });
});

router.get("/:id", (request, response) => {
  const user = findUserById(request.params.id);
  if (!user) {
    return response.status(404).json({ error: "not found" });
  }
  return response.json({ user });
});

router.delete("/:id", requireRole("admin"), (request, response) => {
  const result = require("../lib/db").db.prepare("DELETE FROM users WHERE id = ?").run(request.params.id);
  response.json({ deleted: result.changes });
});

module.exports = router;
