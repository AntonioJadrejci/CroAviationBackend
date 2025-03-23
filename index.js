const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const bcrypt = require("bcryptjs"); // Za hashiranje lozinki
const jwt = require("jsonwebtoken"); // Za generiranje JWT tokena
const { MongoClient } = require("mongodb"); // Za povezivanje s MongoDB
const multer = require("multer"); // Za upload slika
const path = require("path");

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use("/uploads", express.static(path.join(__dirname, "uploads"))); // Serve static files

// Konfiguracija za multer (upload slika)
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "uploads/");
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + path.extname(file.originalname)); // Dodaj timestamp kako bi imena bila jedinstvena
  },
});
const upload = multer({ storage });

// Povezivanje s MongoDB
const uri = process.env.MONGO_URI; // Connection string iz .env datoteke
const client = new MongoClient(uri); // Uklonite zastarjele opcije

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
  const newUser = { username, email, password: hashedPassword, numberOfPlanes: 0 };
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

// Ruta za dohvat profila
app.get("/api/profile", async (req, res) => {
  const token = req.headers.authorization.split(" ")[1];
  const decoded = jwt.verify(token, process.env.JWT_SECRET);
  const user = await db.collection("users").findOne({ email: decoded.email });

  if (user) {
    res.json({
      username: user.username,
      profileImage: user.profileImage || "",
      numberOfPlanes: user.numberOfPlanes || 0,
    });
  } else {
    res.status(404).json({ message: "User not found" });
  }
});

// Ruta za upload profilne slike
app.post("/api/upload-profile-image", upload.single("profileImage"), async (req, res) => {
  const token = req.headers.authorization.split(" ")[1];
  const decoded = jwt.verify(token, process.env.JWT_SECRET);
  const user = await db.collection("users").findOne({ email: decoded.email });

  if (user) {
    const profileImage = req.file ? req.file.path : null;
    await db.collection("users").updateOne(
      { _id: user._id },
      { $set: { profileImage } }
    );
    res.json({ profileImage });
  } else {
    res.status(404).json({ message: "User not found" });
  }
});

// Ruta za brisanje računa
app.delete("/api/delete-account", async (req, res) => {
  const token = req.headers.authorization.split(" ")[1];
  const decoded = jwt.verify(token, process.env.JWT_SECRET);
  await db.collection("users").deleteOne({ email: decoded.email });
  res.json({ message: "Account deleted successfully" });
});

// Ruta za dodavanje aviona
app.post("/api/add-plane", upload.single("planeImage"), async (req, res) => {
  const token = req.headers.authorization.split(" ")[1];
  const decoded = jwt.verify(token, process.env.JWT_SECRET);
  const user = await db.collection("users").findOne({ email: decoded.email });

  if (user) {
    const planeData = {
      airport: req.body.airport,
      planeModel: req.body.planeModel,
      airline: req.body.airline,
      registration: req.body.registration,
      arrivalDate: req.body.arrivalDate,
      departureDate: req.body.departureDate,
      planeImage: req.file ? req.file.path : null, // Spremi putanju do slike
      userId: user._id,
    };

    await db.collection("planes").insertOne(planeData);
    await db.collection("users").updateOne(
      { _id: user._id },
      { $inc: { numberOfPlanes: 1 } }
    );

    res.json({ message: "Plane added successfully" });
  } else {
    res.status(404).json({ message: "User not found" });
  }
});

// Ruta za dohvat aviona po zračnoj luci
app.get("/api/planes/:airport", async (req, res) => {
  const { airport } = req.params;
  const planes = await db.collection("planes").find({ airport }).toArray();
  res.json(planes);
});

// Pokretanje servera
app.listen(PORT, () => {
  console.log(`Server je pokrenut na portu ${PORT}`);
});