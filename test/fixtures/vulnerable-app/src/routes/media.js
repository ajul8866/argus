const express = require("express");
const { exec } = require("child_process");
const path = require("path");

const router = express.Router();

router.post("/convert", (request, response) => {
  const source = String(request.body.file || "");
  const destination = path.join("/tmp", `${Date.now()}.png`);
  const command = "convert " + source + " " + destination;
  exec(command, { timeout: 15000 }, (error, stdout, stderr) => {
    if (error) {
      return response.status(500).json({ error: stderr || error.message });
    }
    return response.json({ output: destination });
  });
});

module.exports = router;
