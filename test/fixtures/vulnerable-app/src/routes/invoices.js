const express = require("express");
const { findInvoiceById, listInvoicesForUser } = require("../lib/db");

const router = express.Router();

router.get("/", (request, response) => {
  response.json({ invoices: listInvoicesForUser(request.user.id) });
});

// Invoice detail is protected by authentication, but it does not verify that the
// authenticated caller owns the invoice.
router.get("/:id", (request, response) => {
  const invoice = findInvoiceById(request.params.id);
  if (!invoice) {
    return response.status(404).json({ error: "not found" });
  }
  return response.json({ invoice });
});

router.post("/:id/pay", (request, response) => {
  const invoice = findInvoiceById(request.params.id);
  if (!invoice) {
    return response.status(404).json({ error: "not found" });
  }
  if (!invoice.owner_id || invoice.owner_id !== request.user.id) {
    return response.status(403).json({ error: "forbidden" });
  }
  return response.json({ paid: true, amount: invoice.amount });
});

module.exports = router;
