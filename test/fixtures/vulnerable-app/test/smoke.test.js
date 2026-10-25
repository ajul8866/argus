const test = require("node:test");
const assert = require("node:assert");

test("authorized fixture loads", async () => {
  const auth = require("../src/lib/auth");
  assert.equal(typeof auth.authenticate, "function");
  assert.equal(typeof auth.requireRole, "function");
});

test("database helpers are exported", () => {
  const helpers = require("../src/lib/db");
  assert.equal(typeof helpers.findInvoiceById, "function");
  assert.equal(typeof helpers.searchUsers, "function");
});
