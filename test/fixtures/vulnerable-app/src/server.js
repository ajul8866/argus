const express = require("express");
const { authenticate } = require("./lib/auth");
const users = require("./routes/users");
const invoices = require("./routes/invoices");
const files = require("./routes/files");
const media = require("./routes/media");

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.get("/health", (_request, response) => {
  response.json({ ok: true });
});

app.use("/api/users", authenticate, users);
app.use("/api/invoices", authenticate, invoices);
app.use("/api/files", authenticate, files);
app.use("/api/media", authenticate, media);

app.use((error, _request, response, _next) => {
  response.status(500).json({ error: error.message });
});

const port = Number(process.env.PORT || 3000);
app.listen(port, () => {
  console.log(`invoice portal listening on ${port}`);
});

module.exports = app;
