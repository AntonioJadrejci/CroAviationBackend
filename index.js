const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());

// Testna ruta
app.get("/api/endpoint", (req, res) => {
  res.json({ message: "Poruka s backenda!" });
});

// Ruta za prijavu
app.post("/api/login", (req, res) => {
  const { email, password } = req.body;

  // Ovdje dodajte logiku za provjeru korisnika u bazi podataka
  // Primjer:
  if (email === "test@example.com" && password === "password") {
    res.json({ message: "Prijava uspješna", token: "dummy-token" });
  } else {
    res.status(401).json({ message: "Neispravni podaci za prijavu" });
  }
});

// Ruta za registraciju
app.post("/api/register", (req, res) => {
  const { username, email, password } = req.body;

  // Ovdje dodajte logiku za registraciju korisnika u bazi podataka
  // Primjer:
  res.json({ message: "Registracija uspješna", token: "dummy-token" });
});

// Ruta za odjavu
app.post("/api/logout", (req, res) => {
  res.json({ message: "Odjava uspješna" });
});

// Pokretanje servera
app.listen(PORT, () => {
  console.log(`Server je pokrenut na portu ${PORT}`);
});