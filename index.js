const express = require("express")
const cors = require("cors")
const dotenv = require("dotenv")
const bcrypt = require("bcryptjs")
const jwt = require("jsonwebtoken")
const { MongoClient } = require("mongodb")
const multer = require("multer")
const path = require("path")

dotenv.config()

const app = express()
const PORT = process.env.PORT || 3000

// Enhanced CORS configuration
const corsOptions = {
  origin: 'http://localhost:8080',
  optionsSuccessStatus: 200
}

// Middleware
app.use(cors(corsOptions))
app.use(express.json())
app.use(express.urlencoded({ extended: true }))
app.use("/uploads", express.static(path.join(__dirname, "uploads")))

// Multer configuration
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "uploads/")
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + path.extname(file.originalname))
  }
})
const upload = multer({ storage })

// MongoDB connection
const uri = process.env.MONGO_URI
const client = new MongoClient(uri)

let db

// Add plane endpoint
app.post("/api/add-plane", authenticateToken, upload.single('planeImage'), async (req, res) => {
  try {
    const { airport, planeModel, airline, registration, arrivalDate, departureDate } = req.body
    const userId = req.user.email // Using email as user identifier

    if (!airport || !planeModel || !airline || !registration) {
      return res.status(400).json({ message: "Required fields missing" })
    }

    const planeData = {
      airport,
      planeModel,
      airline,
      registration,
      arrivalDate: arrivalDate || new Date(),
      departureDate: departureDate || new Date(),
      userId,
      planeImage: req.file ? req.file.path : "",
      createdAt: new Date()
    }

    // Insert plane
    const result = await db.collection("planes").insertOne(planeData)

    // Update user's plane count
    await db.collection("users").updateOne(
      { email: userId },
      { $inc: { numberOfPlanes: 1 } }
    )

    res.status(201).json({
      message: "Plane added successfully",
      planeId: result.insertedId
    })
  } catch (err) {
    console.error("Add plane error:", err)
    res.status(500).json({ message: "Error adding plane" })
  }
})

// Upload profile image endpoint
app.post("/api/upload-profile-image", authenticateToken, upload.single('profileImage'), async (req, res) => {
  try {
    const userId = req.user.email

    if (!req.file) {
      return res.status(400).json({ message: "No image uploaded" })
    }

    await db.collection("users").updateOne(
      { email: userId },
      { $set: { profileImage: req.file.path } }
    )

    res.json({
      message: "Profile image uploaded successfully",
      profileImage: req.file.path
    })
  } catch (err) {
    console.error("Profile image upload error:", err)
    res.status(500).json({ message: "Error uploading profile image" })
  }
})

// Delete account endpoint
app.delete("/api/delete-account", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.email

    // Delete user's planes first
    await db.collection("planes").deleteMany({ userId })

    // Then delete user
    await db.collection("users").deleteOne({ email: userId })

    res.json({ message: "Account deleted successfully" })
  } catch (err) {
    console.error("Delete account error:", err)
    res.status(500).json({ message: "Error deleting account" })
  }
})

async function startServer() {
  try {
    await client.connect()
    db = client.db("CroAviation")
    console.log("Connected to MongoDB database")

    // Create indexes if they don't exist
    await db.collection("users").createIndex({ email: 1 }, { unique: true })
    await db.collection("planes").createIndex({ airport: 1, airline: 1 })

    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`)
    })
  } catch (err) {
    console.error("Database connection error:", err)
    process.exit(1)
  }
}

// Authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization']
  const token = authHeader && authHeader.split(' ')[1]

  if (!token) return res.status(401).json({ message: 'No token provided' })

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      if (err.name === 'TokenExpiredError') {
        return res.status(403).json({
          message: 'Token expired',
          expiredAt: err.expiredAt
        })
      }
      return res.status(403).json({ message: 'Invalid token' })
    }
    req.user = user
    next()
  })
}

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({
    status: 'OK',
    database: db ? 'Connected' : 'Disconnected'
  })
})

// Token refresh endpoint
app.post("/api/refresh-token", (req, res) => {
  const refreshToken = req.body.token
  if (!refreshToken) return res.status(401).json({ message: 'No refresh token provided' })

  jwt.verify(refreshToken, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid refresh token' })

    const newAccessToken = jwt.sign({ email: user.email }, process.env.JWT_SECRET, { expiresIn: '1h' })
    res.json({ token: newAccessToken })
  })
})

// User registration
app.post("/api/register", async (req, res) => {
  try {
    const { username, email, password } = req.body

    if (!username || !email || !password) {
      return res.status(400).json({ message: "All fields are required" })
    }

    const existingUser = await db.collection("users").findOne({ email })
    if (existingUser) {
      return res.status(400).json({ message: "Email already in use" })
    }

    const hashedPassword = await bcrypt.hash(password, 10)
    const newUser = {
      username,
      email,
      password: hashedPassword,
      numberOfPlanes: 0,
      profileImage: "",
      createdAt: new Date()
    }

    await db.collection("users").insertOne(newUser)

    const token = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: "1h" })
    const refreshToken = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: "7d" })

    res.status(201).json({
      message: "Registration successful",
      token,
      refreshToken
    })
  } catch (err) {
    console.error("Registration error:", err)
    res.status(500).json({ message: "Internal server error" })
  }
})

// User login
app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body

    const user = await db.collection("users").findOne({ email })
    if (!user) {
      return res.status(400).json({ message: "Invalid credentials" })
    }

    const isMatch = await bcrypt.compare(password, user.password)
    if (!isMatch) {
      return res.status(400).json({ message: "Invalid credentials" })
    }

    const token = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: "1h" })
    const refreshToken = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: "7d" })

    res.json({
      message: "Login successful",
      token,
      refreshToken,
      username: user.username
    })
  } catch (err) {
    console.error("Login error:", err)
    res.status(500).json({ message: "Internal server error" })
  }
})

// User profile
app.get("/api/profile", authenticateToken, async (req, res) => {
  try {
    const user = await db.collection("users").findOne({ email: req.user.email })
    if (!user) {
      return res.status(404).json({ message: "User not found" })
    }

    res.json({
      username: user.username,
      profileImage: user.profileImage || "",
      numberOfPlanes: user.numberOfPlanes || 0
    })
  } catch (err) {
    console.error("Profile error:", err)
    res.status(500).json({ message: "Internal server error" })
  }
})

// Airline endpoints with improved error handling
app.get("/api/airlines/:airport", async (req, res) => {
  try {
    if (!db) {
      return res.status(503).json({ message: "Database not connected" })
    }

    const { airport } = req.params
    console.log(`Fetching airlines for airport: ${airport}`)

    const airlines = await db.collection("planes").distinct("airline", { airport })
    res.json(airlines)
  } catch (err) {
    console.error("Error fetching airlines:", err)
    res.status(500).json({ message: "Error fetching airlines" })
  }
})

app.get("/api/planes/:airport", async (req, res) => {
  try {
    const { airport } = req.params
    const planes = await db.collection("planes").find({ airport }).toArray()
    res.json(planes)
  } catch (err) {
    console.error("Error fetching planes:", err)
    res.status(500).json({ message: "Error fetching planes" })
  }
})

app.get("/api/planes/:airport/:airline", async (req, res) => {
  try {
    const { airport, airline } = req.params
    const planes = await db.collection("planes").find({ airport, airline }).toArray()

    const planesWithUsers = await Promise.all(
      planes.map(async plane => {
        const user = await db.collection("users").findOne({ _id: plane.userId })
        return {
          ...plane,
          username: user ? user.username : "Unknown"
        }
      })
    )

    res.json(planesWithUsers)
  } catch (err) {
    console.error("Error fetching airline planes:", err)
    res.status(500).json({ message: "Error fetching airline planes" })
  }
})

// Start the server
startServer()