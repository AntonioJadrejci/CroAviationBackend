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

// Pokretanje servera
app.listen(PORT, () => {
  console.log(`Server je pokrenut na portu ${PORT}`);
});