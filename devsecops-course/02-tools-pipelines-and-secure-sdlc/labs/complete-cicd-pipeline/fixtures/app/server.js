// Fixture "source code" for the fake SAST tool. It is never executed.
const express = require("express");
const app = express();

app.get("/healthz", (req, res) => res.send("ok"));

app.get("/api/orders/:id", (req, res) => {
  const order = db.findOrder(req.params.id); // parameterised: fine
  res.json(order);
});

app.post("/api/reset", (req, res) => {
  const resetCode = Math.random().toString(36).slice(2); // weak randomness for a security code
  mailer.send(req.body.email, resetCode);
  res.sendStatus(204);
});

app.listen(3000);
