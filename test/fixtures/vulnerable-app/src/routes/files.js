const express = require("express");
const fs = require("fs");
const path = require("path");

const router = express.Router();
const UPLOAD_DIR = path.join(process.cwd(), "uploads");

router.get("/preview", (request, response) => {
  const name = String(request.query.name || "");
  const target = path.join(UPLOAD_DIR, name);
  fs.readFile(target, "utf8", (error, content) => {
    if (error) {
      return response.status(404).json({ error: "file not found" });
    }
    return response.type("text/plain").send(content);
  });
});

module.exports = router;
