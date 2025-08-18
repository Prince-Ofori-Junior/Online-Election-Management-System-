const { Pool } = require("pg");
require("dotenv").config();

const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    password: process.env.DB_PASS,
    port: parseInt(process.env.DB_PORT),
    ssl: process.env.DB_SSL === "true" ? { rejectUnauthorized: false } : false, // Use SSL conditionally
});

pool.on("connect", () => {
    console.log("✅ Connected to the database");
});

pool.on("error", (err) => {
    console.error("❌ Database connection error:", err.message);
});

module.exports = pool;
