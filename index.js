const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { MongoClient } = require("mongodb");
const multer = require("multer");
const path = require("path");

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

// Konfiguracija za multer
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "uploads/");
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + path.extname(file.originalname));
  },
});
const upload = multer({ storage });

// Povezivanje s MongoDB
const uri = process.env.MONGO_URI;
const client = new MongoClient(uri);

let db;

client.connect().then(() => {
  db = client.db("CroAviation");
  console.log("Povezano s bazom podataka");
}).catch(err => {
  console.error("Greška pri povezivanju s bazom podataka:", err);
  process.exit(1);
});

// Middleware za provjeru tokena
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.sendStatus(401);

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      if (err.name === 'TokenExpiredError') {
        return res.status(403).json({ message: 'Token expired', expiredAt: err.expiredAt });
      }
      return res.sendStatus(403);
    }
    req.user = user;
    next();
  });
};

// Ruta za refresh tokena
app.post("/api/refresh-token", (req, res) => {
  const refreshToken = req.body.token;
  if (!refreshToken) return res.sendStatus(401);

  jwt.verify(refreshToken, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);

    // Generiraj novi access token
    const newAccessToken = jwt.sign({ email: user.email }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ token: newAccessToken });
  });
});

// Ruta za registraciju
app.post("/api/register", async (req, res) => {
  const { username, email, password } = req.body;

  const existingUser = await db.collection("users").findOne({ email });
  if (existingUser) {
    return res.status(400).json({ message: "Korisnik s tim emailom već postoji" });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = { username, email, password: hashedPassword, numberOfPlanes: 0, profileImage: "" };
  await db.collection("users").insertOne(newUser);

  const token = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: "1h" });
  const refreshToken = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: "7d" });

  res.status(201).json({
    message: "Registracija uspješna",
    token,
    refreshToken
  });
});

// Ruta za prijavu
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;

  const user = await db.collection("users").findOne({ email });
  if (!user) {
    return res.status(400).json({ message: "Neispravni podaci za prijavu" });
  }

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) {
    return res.status(400).json({ message: "Neispravni podaci za prijavu" });
  }

  const token = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: "1h" });
  const refreshToken = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: "7d" });

  res.status(200).json({
    message: "Prijava uspješna",
    token,
    refreshToken
  });
});

// Ruta za odjavu
app.post("/api/logout", (req, res) => {
  res.json({ message: "Odjava uspješna" });
});

// Ruta za dohvat profila
app.get("/api/profile", authenticateToken, async (req, res) => {
  const user = await db.collection("users").findOne({ email: req.user.email });

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
app.post("/api/upload-profile-image", authenticateToken, upload.single("profileImage"), async (req, res) => {
  const user = await db.collection("users").findOne({ email: req.user.email });

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
app.delete("/api/delete-account", authenticateToken, async (req, res) => {
  await db.collection("users").deleteOne({ email: req.user.email });
  res.json({ message: "Account deleted successfully" });
});

// Ruta za dodavanje aviona
app.post("/api/add-plane", authenticateToken, upload.single("planeImage"), async (req, res) => {
  const user = await db.collection("users").findOne({ email: req.user.email });

  if (user) {
    const planeData = {
      airport: req.body.airport,
      planeModel: req.body.planeModel,
      airline: req.body.airline,
      registration: req.body.registration,
      arrivalDate: req.body.arrivalDate,
      departureDate: req.body.departureDate,
      planeImage: req.file ? req.file.path : null,
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