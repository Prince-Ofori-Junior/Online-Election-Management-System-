require("dotenv").config();
const express = require("express");
const cors = require("cors");
const multer = require("multer");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Joi = require("joi");
const pool = require("./db");
const path = require("path");
const fs = require("fs");
const nodemailer = require("nodemailer");
const crypto = require("crypto"); // For generating a secure random reset token
const rateLimit = require("express-rate-limit");
const morgan = require("morgan");

// --- Debug ---
console.log("EMAIL_USER:", process.env.EMAIL_USER);
console.log("EMAIL_PASS:", process.env.EMAIL_PASS ? "✅ Loaded" : "❌ NOT LOADED");

// --- Constants / Paths ---
const uploadDir = "./uploads";
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir);
}

const app = express();
app.use(express.static("public"));

// --- CORS (GitHub Pages frontend domain only) ---
const corsOptions = {
  origin: "https://prince-ofori-junior.github.io",
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
  credentials: true,
  optionsSuccessStatus: 204,
};
app.use(cors(corsOptions));

// --- Body / Logging ---
app.use(express.json({ limit: "1mb" }));
app.use(morgan("dev")); // Logs HTTP requests in development

// --- Rate limits ---
const forgotPasswordLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 mins
  max: 5,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: "Too many password reset attempts. Please try again later.",
});

// --- Security: required secrets ---
if (!process.env.JWT_SECRET) {
  console.error("❌ ERROR: Missing JWT_SECRET in environment!");
  process.exit(1);
}

// Optional but recommended: configure this in Render to avoid hardcoding
const FRONTEND_BASE_URL =
  process.env.FRONTEND_BASE_URL ||
  "https://prince-ofori-junior.github.io/Online-Election-Management-System-frontend";

// --- Multer (file uploads) ---
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => cb(null, Date.now() + "-" + file.originalname),
});

const upload = multer({
  storage,
  fileFilter: (req, file, cb) => {
    const filetypes = /jpeg|jpg|png/;
    const extname = filetypes.test(
      path.extname(file.originalname).toLowerCase()
    );
    const mimetype = filetypes.test(file.mimetype);
    if (extname && mimetype) cb(null, true);
    else cb(new Error("Error: Images Only!"));
  },
}).single("image");

app.use("/uploads", express.static(path.join(__dirname, "uploads")));

// --- JWT Middleware ---
const authenticateToken = (req, res, next) => {
  const token = req.header("Authorization")?.split(" ")[1];
  if (!token) return res.status(403).json({ error: "Access denied" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    res.status(401).json({ error: "Invalid token" });
  }
};

// --- Error handler (must come after routes that may throw in middlewares) ---
app.use((err, req, res, next) => {
  console.error("Error:", err.message);
  res.status(err.status || 500).json({ error: err.message || "Internal Server Error" });
});

// --- Router setup ---
const router = express.Router();
app.use("/uploads", express.static(uploadDir));

// ===== AUTH ROUTES =====
const userSchema = Joi.object({
  name: Joi.string().min(3).max(50).required(),
  email: Joi.string().email().required(),
  password: Joi.string().min(6).required(),
  gender: Joi.string().valid("male", "female", "other").optional(),
  birthdate: Joi.date().optional(),
  phone: Joi.string().optional(),
  address: Joi.string().optional(),
  role: Joi.string().valid("voter").optional(), // enforce only 'voter' role from frontend
});

// ✅ REGISTER (voters only)
router.post("/auth/register", async (req, res, next) => {
  const { name, email, password, gender, birthdate, phone, address } = req.body;
  const role = "voter"; // ⛔ prevent admin self-registration

  const { error } = userSchema.validate({
    name,
    email,
    password,
    gender,
    birthdate,
    phone,
    address,
    role,
  });
  if (error) return res.status(400).json({ error: error.details[0].message });

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = await pool.query(
      `INSERT INTO users (name, email, password, gender, birthdate, phone, address, role)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *`,
      [name, email, hashedPassword, gender, birthdate, phone, address, role]
    );
    res.status(201).json(newUser.rows[0]);
  } catch (error) {
    next(error);
  }
});

// 🔐 Create initial admin manually (disabled in production)
router.post("/auth/create-admin", async (req, res) => {
  if (process.env.NODE_ENV === "production") {
    return res.status(403).json({ error: "This route is disabled in production" });
  }

  const { name, email, password } = req.body;
  if (!name || !email || !password)
    return res.status(400).json({ error: "All fields required" });

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const newAdmin = await pool.query(
      `INSERT INTO users (name, email, password, role)
       VALUES ($1, $2, $3, 'admin') RETURNING *`,
      [name, email, hashedPassword]
    );
    res.status(201).json({ message: "Admin created", user: newAdmin.rows[0] });
  } catch (error) {
    res.status(500).json({ error: "Failed to create admin" });
  }
});

// ✅ LOGIN
router.post("/auth/login", async (req, res, next) => {
  const { email, password } = req.body;

  try {
    const result = await pool.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);
    if (result.rows.length === 0)
      return res.status(404).json({ error: "User not found" });

    const user = result.rows[0];
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(401).json({ error: "Invalid credentials" });

    const token = jwt.sign(
      { id: user.id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );
    res.json({ token });
  } catch (error) {
    next(error);
  }
});

// ===== ADMIN FUNCTIONS =====
router.get("/users", authenticateToken, async (req, res) => {
  if (req.user.role !== "admin")
    return res.status(403).json({ error: "Admins only" });

  try {
    const result = await pool.query(
      `SELECT id, name, email, birthdate, address, phone, role
       FROM users
       ORDER BY id ASC`
    );
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: "Failed to fetch users" });
  }
});

// ===== ELECTION & VOTING =====
router.post("/elections/add", authenticateToken, async (req, res) => {
  if (req.user.role !== "admin")
    return res.status(403).json({ error: "Admins only" });

  const { name, date } = req.body;
  if (!name || !date) return res.status(400).json({ error: "Name and date required" });

  try {
    const result = await pool.query(
      "INSERT INTO elections (name, date) VALUES ($1, $2) RETURNING *",
      [name, date]
    );
    res.status(201).json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: "Failed to create election" });
  }
});

router.get("/elections", async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM elections");
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: "Failed to fetch elections" });
  }
});

router.post("/elections/:election_id/vote", authenticateToken, async (req, res) => {
  const { election_id } = req.params;
  const { candidateId } = req.body;
  const userId = req.user.id;

  try {
    const existingVote = await pool.query(
      "SELECT * FROM votes WHERE user_id = $1 AND election_id = $2",
      [userId, election_id]
    );

    if (existingVote.rows.length > 0) {
      return res.status(400).json({ error: "You already voted in this election" });
    }

    await pool.query(
      "INSERT INTO votes (user_id, candidate_id, election_id) VALUES ($1, $2, $3)",
      [userId, candidateId, election_id]
    );

    res.json({ message: "Vote recorded successfully" });
  } catch (error) {
    res.status(500).json({ error: "Voting failed" });
  }
});

// ===== CANDIDATES =====
router.post("/candidates/add", authenticateToken, upload, async (req, res) => {
  if (req.user.role !== "admin")
    return res.status(403).json({ error: "Admins only" });

  const { name, party, election_id } = req.body;
  const image_url = req.file ? req.file.path : null;

  try {
    const check = await pool.query("SELECT * FROM elections WHERE id = $1", [
      election_id,
    ]);
    if (check.rows.length === 0)
      return res.status(400).json({ error: "Invalid election ID" });

    const result = await pool.query(
      "INSERT INTO candidates (name, party, image_url, election_id) VALUES ($1, $2, $3, $4) RETURNING *",
      [name, party, image_url, election_id]
    );
    res.status(201).json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: "Failed to add candidate" });
  }
});

router.get("/elections/:election_id/candidates", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM candidates WHERE election_id = $1",
      [req.params.election_id]
    );
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: "Failed to fetch candidates" });
  }
});

// ===== PASSWORD RESET =====

// ✅ Forgot password (with rate limiting + live frontend link)
router.post("/auth/forgot-password", forgotPasswordLimiter, async (req, res) => {
  const { email } = req.body;

  try {
    // Check if the user exists
    const result = await pool.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    const user = result.rows[0];

    // Generate a reset token (store as-is with expiry, since you verify exactly later)
    const resetToken = crypto.randomBytes(32).toString("hex");
    const expirationTime = Date.now() + 3600000; // 1 hour

    await pool.query(
      "UPDATE users SET reset_token = $1, reset_token_expiry = $2 WHERE id = $3",
      [resetToken, expirationTime, user.id]
    );

    // ✅ LIVE FRONTEND LINK (uses env FRONTEND_BASE_URL)
    const resetLink = `${FRONTEND_BASE_URL}/reset-password.html?token=${resetToken}&email=${encodeURIComponent(
      email
    )}`;

    // Send the reset email
    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Password Reset Request",
      text: `You requested a password reset. Open the link below to reset your password:\n\n${resetLink}\n\nIf you didn't request this, you can ignore this email.`,
      html: `<p>You requested a password reset. Click the link below to reset your password:</p>
             <p><a href="${resetLink}">${resetLink}</a></p>
             <p>If you didn't request this, you can ignore this email.</p>`,
    };

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.error("❌ Email sending failed:", error);
        return res.status(500).json({ error: "Failed to send email" });
      }
      console.log("✅ Email sent:", info.response);
      res.json({ message: "Password reset email sent" });
    });
  } catch (error) {
    console.error("Forgot-password error:", error);
    res.status(500).json({ error: "Error while processing the request" });
  }
});

// ✅ Reset password
router.post("/auth/reset-password", async (req, res) => {
  const { token, newPassword, email } = req.body;

  if (!token || !newPassword || !email) {
    return res.status(400).json({ error: "Token, email and newPassword are required" });
  }

  try {
    // Find user with the matching reset token and check expiry
    const result = await pool.query(
      "SELECT * FROM users WHERE email = $1 AND reset_token = $2 AND reset_token_expiry > $3",
      [email, token, Date.now()]
    );

    if (result.rows.length === 0) {
      return res.status(400).json({ error: "Invalid or expired token" });
    }

    const user = result.rows[0];

    // Hash the new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update the password and clear the reset token
    await pool.query(
      "UPDATE users SET password = $1, reset_token = NULL, reset_token_expiry = NULL WHERE id = $2",
      [hashedPassword, user.id]
    );

    res.json({ message: "Password successfully updated" });
  } catch (error) {
    console.error("Reset-password error:", error);
    res.status(500).json({ error: "Error while resetting the password" });
  }
});

// ===== USER STATUS =====
router.put("/users/:user_id/status", authenticateToken, async (req, res) => {
  if (req.user.role !== "admin")
    return res.status(403).json({ error: "Admins only" });

  const { user_id } = req.params;
  const { status } = req.body;

  if (!["approved", "pending"].includes(status)) {
    return res.status(400).json({ error: "Invalid status value" });
  }

  try {
    const updated = await pool.query(
      "UPDATE users SET status = $1 WHERE id = $2 RETURNING *",
      [status, user_id]
    );

    if (updated.rows.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json({ message: "User status updated", user: updated.rows[0] });
  } catch (error) {
    console.error("Failed to update user status:", error);
    res.status(500).json({ error: "Failed to update user status" });
  }
});

// ===== RESULTS =====
router.get("/results", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT 
          c.id, 
          c.name, 
          c.party, 
          c.image_url, 
          e.name AS election, 
          COUNT(v.id) AS votes
      FROM candidates c
      JOIN elections e ON c.election_id = e.id
      LEFT JOIN votes v ON c.id = v.candidate_id
      GROUP BY c.id, e.name
      ORDER BY e.name, votes DESC
    `
    );
    res.json(result.rows);
  } catch (error) {
    console.error("Failed to load results:", error);
    res.status(500).json({ message: "Failed to fetch results." });
  }
});

// --- Health / root ---
router.get("/", (req, res) => {
  res.send("✅ Online Election Management System backend is running...");
});

// --- Mount router ---
app.use(router);

// --- Start server (Render uses dynamic PORT) ---
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
