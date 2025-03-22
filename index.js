const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const bcrypt = require("bcryptjs"); // Za hashiranje lozinki
const jwt = require("jsonwebtoken"); // Za generiranje JWT tokena
const { MongoClient } = require("mongodb"); // Za povezivanje s MongoDB

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());

// Povezivanje s MongoDB
const uri = process.env.MONGO_URI; // Connection string iz .env datoteke
const client = new MongoClient(uri, { useNewUrlParser: true, useUnifiedTopology: true });

let db;

client.connect().then(() => {
  db = client.db("CroAviation"); // Naziv baze podataka
  console.log("Povezano s bazom podataka");
}).catch(err => {
  console.error("Greška pri povezivanju s bazom podataka:", err);
  process.exit(1); // Zaustavi aplikaciju ako se ne može povezati s bazom podataka
});

// Ruta za registraciju
app.post("/api/register", async (req, res) => {
  const { username, email, password } = req.body;

  // Provjera postoji li korisnik s istim emailom
  const existingUser = await db.collection("users").findOne({ email });
  if (existingUser) {
    return res.status(400).json({ message: "Korisnik s tim emailom već postoji" });
  }

  // Hashiranje lozinke
  const hashedPassword = await bcrypt.hash(password, 10);

  // Spremanje korisnika u bazu podataka
  const newUser = { username, email, password: hashedPassword };
  await db.collection("users").insertOne(newUser);

  // Generiranje JWT tokena
  const token = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: "1h" });

  res.status(201).json({ message: "Registracija uspješna", token });
});

// Ruta za prijavu
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;

  // Pronalaženje korisnika u bazi podataka
  const user = await db.collection("users").findOne({ email });
  if (!user) {
    return res.status(400).json({ message: "Neispravni podaci za prijavu" });
  }

  // Provjera lozinke
  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) {
    return res.status(400).json({ message: "Neispravni podaci za prijavu" });
  }

  // Generiranje JWT tokena
  const token = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: "1h" });

  res.status(200).json({ message: "Prijava uspješna", token });
});

// Ruta za odjavu
app.post("/api/logout", (req, res) => {
  res.json({ message: "Odjava uspješna" });
});

// Pokretanje servera
app.listen(PORT, () => {
  console.log(`Server je pokrenut na portu ${PORT}`);
});