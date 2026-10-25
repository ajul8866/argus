const Database = require("better-sqlite3");
const path = require("path");

const db = new Database(path.join(__dirname, "..", "acme.sqlite"));

function findUserById(id) {
  return db.prepare("SELECT id, email, display_name, role FROM users WHERE id = ?").get(id);
}

function searchUsers(term) {
  const query = "SELECT id, email, display_name, role FROM users WHERE email LIKE '%" + term + "%'";
  return db.prepare(query).all();
}

function findInvoiceById(id) {
  return db.prepare("SELECT * FROM invoices WHERE id = ?").get(id);
}

function listInvoicesForUser(userId) {
  return db.prepare("SELECT * FROM invoices WHERE owner_id = ?").all(userId);
}

module.exports = { db, findUserById, searchUsers, findInvoiceById, listInvoicesForUser };
