const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { MongoClient, ServerApiVersion } = require("mongodb");
const multer = require("multer");
const path = require("path");
const fs = require("fs");

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;


const corsOptions = {
  origin: (origin, callback) => {

    const allowedOrigins = [
      process.env.FRONTEND_URL,
      'https://croaviationfrontend.onrender.com',
      'https://croaviationfrontend.onrender.com',
      'http://localhost:8080',
      'http://localhost:3000'
    ].filter(Boolean);


    if (!origin) return callback(null, true);


    const originIsAllowed = allowedOrigins.some(allowedOrigin =>
      origin === allowedOrigin ||
      origin.startsWith(allowedOrigin) ||
      new URL(origin).hostname === new URL(allowedOrigin).hostname
    );

    if (originIsAllowed) {
      return callback(null, true);
    }


    if (process.env.NODE_ENV === 'production') {
      console.warn(`CORS blokiran za origin: ${origin}`);
      return callback(new Error('Not allowed by CORS'), false);
    }


    return callback(null, true);
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  credentials: true,
  optionsSuccessStatus: 200,
  maxAge: 86400
};


app.use(cors(corsOptions));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

app.options('*', cors(corsOptions));
app.options("/api/upload-profile-image", cors(corsOptions));



const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    const uploadDir = path.join(__dirname, "uploads");
    fs.mkdirSync(uploadDir, { recursive: true });
    cb(null, uploadDir);
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + path.extname(file.originalname));
  }
});
const upload = multer({ storage });


const uri = process.env.MONGO_URI;
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
  maxPoolSize: 50,
  connectTimeoutMS: 10000,
  socketTimeoutMS: 45000
});

let db;


client.on('serverOpening', () => {
  console.log('MongoDB connection opening');
});

client.on('serverClosed', () => {
  console.log('MongoDB connection closed');
});

client.on('topologyClosed', () => {
  console.log('MongoDB topology closed');
});



const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ message: 'No token provided' });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      if (err.name === 'TokenExpiredError') {
        return res.status(403).json({
          message: 'Token expired',
          expiredAt: err.expiredAt
        });
      }
      return res.status(403).json({ message: 'Invalid token' });
    }
    req.user = user;
    next();
  });
};


app.get('/api/health', async (req, res) => {
  try {
    const dbStatus = db ? await client.db().admin().ping() : false;

    res.json({
      status: 'OK',
      database: dbStatus ? 'Connected' : 'Disconnected',
      timestamp: new Date().toISOString(),
      uptime: process.uptime()
    });
  } catch (err) {
    res.status(500).json({
      status: 'ERROR',
      database: 'Connection failed',
      error: err.message
    });
  }
});


app.post("/api/refresh-token", (req, res) => {
  const refreshToken = req.body.token;
  if (!refreshToken) return res.status(401).json({ message: 'No refresh token provided' });

  jwt.verify(refreshToken, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid refresh token' });
    const newAccessToken = jwt.sign({ email: user.email }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ token: newAccessToken });
  });
});


app.post("/api/register", async (req, res) => {
  try {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ message: "All fields are required" });
    }

    const existingUser = await db.collection("users").findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: "Email already in use" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = {
      username,
      email,
      password: hashedPassword,
      numberOfPlanes: 0,
      profileImage: "",
      createdAt: new Date()
    };

    await db.collection("users").insertOne(newUser);

    const token = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: "1h" });
    const refreshToken = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: "7d" });

    res.status(201).json({
      message: "Registration successful",
      token,
      refreshToken
    });
  } catch (err) {
    console.error("Registration error:", err);
    res.status(500).json({ message: "Internal server error" });
  }
});


app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await db.collection("users").findOne({ email });
    if (!user) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    const token = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: "1h" });
    const refreshToken = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: "7d" });

    res.json({
      message: "Login successful",
      token,
      refreshToken,
      username: user.username
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ message: "Internal server error" });
  }
});


app.get("/api/profile", authenticateToken, async (req, res) => {
  try {
    const user = await db.collection("users").findOne({ email: req.user.email });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    res.json({
      username: user.username,
      profileImage: user.profileImage || "",
      numberOfPlanes: user.numberOfPlanes || 0
    });
  } catch (err) {
    console.error("Profile error:", err);
    res.status(500).json({ message: "Internal server error" });
  }
});


app.post("/api/add-plane", authenticateToken, upload.single('planeImage'), async (req, res) => {
  console.log("Add plane request received");
  console.log("Files:", req.file);

  try {
    const { airport, planeModel, airline, registration, arrivalDate, departureDate } = req.body;
    const userId = req.user.email;

    if (!airport || !planeModel || !airline || !registration) {
      return res.status(400).json({ message: "Required fields missing" });
    }

    const planeData = {
      airport,
      planeModel,
      airline,
      registration,
      arrivalDate: arrivalDate || new Date(),
      departureDate: departureDate || new Date(),
      userId,
      planeImage: req.file ? `/uploads/${req.file.filename}` : "",
      createdAt: new Date()
    };

    const result = await db.collection("planes").insertOne(planeData);
    await db.collection("users").updateOne(
      { email: userId },
      { $inc: { numberOfPlanes: 1 } }
    );

    res.status(201).json({
      message: "Plane added successfully",
      planeId: result.insertedId
    });
  } catch (err) {
    console.error("Add plane error:", err);
    res.status(500).json({ message: "Error adding plane" });
  }
});


app.options("/api/upload-profile-image", cors(corsOptions));

app.post("/api/upload-profile-image", authenticateToken, upload.single('profileImage'), async (req, res) => {
  try {
    const userId = req.user.email;

    if (!req.file) {
      return res.status(400).json({ message: "No image uploaded" });
    }

    const relativePath = `/uploads/${req.file.filename}`;
    await db.collection("users").updateOne(
      { email: userId },
      { $set: { profileImage: relativePath } }
    );

    res.json({
      message: "Profile image uploaded successfully",
      profileImage: relativePath
    });
  } catch (err) {
    console.error("Profile image upload error:", err);
    res.status(500).json({ message: "Error uploading profile image" });
  }
});


app.delete("/api/delete-account", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.email;
    await db.collection("planes").deleteMany({ userId });
    await db.collection("users").deleteOne({ email: userId });
    res.json({ message: "Account deleted successfully" });
  } catch (err) {
    console.error("Delete account error:", err);
    res.status(500).json({ message: "Error deleting account" });
  }
});


app.get("/api/planes/:airport", async (req, res) => {
  try {
    const { airport } = req.params;
    console.log(`Fetching planes for airport: ${airport}`);

    const planes = await db.collection("planes").find({
      airport: new RegExp(`^${airport}$`, 'i')
    }).toArray();

    console.log(`Found ${planes.length} planes`);

    const planesWithUsers = await Promise.all(
      planes.map(async plane => {
        const user = await db.collection("users").findOne({ email: plane.userId });
        return {
          ...plane,
          username: user ? user.username : "Unknown"
        };
      })
    );

    res.json(planesWithUsers);
  } catch (err) {
    console.error("Error fetching planes:", err);
    res.status(500).json({ message: "Error fetching planes" });
  }
});

process.on('SIGINT', async () => {
  console.log('SIGINT received. Closing server and MongoDB connection...');
  try {
    await client.close();
    console.log('MongoDB connection closed');
    process.exit(0);
  } catch (err) {
    console.error('Error during shutdown:', err);
    process.exit(1);
  }
});


async function startServer() {
  try {
    await client.connect();
    db = client.db("CroAviation");
    console.log("Connected to MongoDB database");


    await db.collection("users").createIndex({ email: 1 }, { unique: true });
    await db.collection("planes").createIndex({ airport: 1 });
    await db.collection("planes").createIndex({ airline: 1 });

    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
    });
  } catch (err) {
    console.error("Database connection error:", err);
    process.exit(1);
  }
}

startServer();