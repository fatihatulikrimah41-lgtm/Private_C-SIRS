require("dotenv").config();
const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcrypt");
const qrcode = require("qrcode");
const jwt = require("jsonwebtoken");

const { generateSecret, generateURI, verify } = require("otplib");

const app = express();

// TAMBAHKAN 1 BARIS INI UNTUK MENGATASI ERROR RENDER PROXY
app.set("trust proxy", 1);

// Enable CORS for your specific frontend URL
app.use(cors({ origin: "*" }));
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,

  max: 4, // Batasi maksimal 4 koneksi serentak agar tidak melewati limit Free Tier
  idleTimeoutMillis: 30000, // Tutup koneksi jika menganggur selama 30 detik
  connectionTimeoutMillis: 5000, // Timeout jika DB lambat merespons
});

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { error: "Terlalu banyak percobaan login. Akun dikunci 15 menit." },
  standardHeaders: true,
  legacyHeaders: false,
});

// ==========================================
// TICKET ROUTES
// ==========================================
app.get("/api/tickets", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM tickets ORDER BY created_at DESC",
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/tickets", async (req, res) => {
  const { pelapor, divisi, kategori, deskripsi, bahaya, status } = req.body;
  if (!pelapor || !deskripsi || !divisi) {
    return res
      .status(400)
      .json({ error: "Pelapor, Divisi, and Deskripsi are required." });
  }

  try {
    const result = await pool.query(
      "INSERT INTO tickets (pelapor, divisi, kategori, deskripsi, bahaya, status) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *",
      [
        pelapor,
        divisi,
        kategori,
        deskripsi,
        bahaya || "Belum Ditentukan",
        status || "Menunggu",
      ],
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Update Ticket Status & Menyimpan Log
app.put("/api/tickets/:id", async (req, res) => {
  const { id } = req.params;
  const { status, bahaya, resolution_note } = req.body;

  try {
    const fields = [];
    const params = [];
    let count = 1;

    if (status !== undefined) {
      fields.push(`status = $${count++}`);
      params.push(status);
    }
    if (bahaya !== undefined) {
      fields.push(`bahaya = $${count++}`);
      params.push(bahaya);
    }
    if (resolution_note !== undefined) {
      fields.push(`resolution_note = $${count++}`);
      params.push(resolution_note);
    }

    // Secara otomatis kunci waktu ketika tiket ditandai Selesai
    if (status === "Selesai") {
      fields.push(`resolved_at = CURRENT_TIMESTAMP`);
    }
    fields.push(`updated_at = CURRENT_TIMESTAMP`);

    if (fields.length === 1)
      return res.status(400).json({ error: "Tidak ada data untuk diupdate" });

    const query = `UPDATE tickets SET ${fields.join(", ")} WHERE id = $${count} RETURNING *`;
    params.push(id);

    const result = await pool.query(query, params);
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Endpoint untuk Menghapus Laporan (False Alarm / Invalid)
app.delete("/api/tickets/:id", async (req, res) => {
  const { id } = req.params;

  try {
    const result = await pool.query(
      "DELETE FROM tickets WHERE id = $1 RETURNING *",
      [id],
    );

    if (result.rowCount === 0) {
      return res
        .status(404)
        .json({ error: "Tiket tidak ditemukan di database." });
    }

    res.json({
      message: "Tiket berhasil dihapus permanen.",
      deleted: result.rows[0],
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ==========================================
// AUTH & MFA ROUTES
// ==========================================
app.post("/api/auth/setup-mfa", async (req, res) => {
  console.log(
    "\n[DEBUG] Permintaan MFA diterima untuk username:",
    req.body.username,
  );

  const { username } = req.body;
  if (!username) return res.status(400).json({ error: "Username required" });

  try {
    // 1. Tes Generate Secret
    const secret = generateSecret();
    console.log("[DEBUG] Secret berhasil dibuat.");

    // 2. Tes Database Connection & Update
    console.log("[DEBUG] Mencoba menyimpan ke database PostgreSQL...");
    const dbRes = await pool.query(
      "UPDATE users SET totp_secret = $1 WHERE username = $2 RETURNING *",
      [secret, username],
    );

    console.log(
      `[DEBUG] Database merespons. Jumlah baris diubah: ${dbRes.rowCount}`,
    );
    if (dbRes.rowCount === 0) {
      console.log(
        `[WARNING] Username ${username} tidak ditemukan di tabel 'users'!`,
      );
    }

    // 3. Tes Generate QR Code Image
    const otpauth = generateURI({
      issuer: "C-SIRS_Dashboard",
      label: username,
      secret: secret,
    });

    const qrImage = await qrcode.toDataURL(otpauth);

    console.log("[DEBUG] Gambar QR berhasil di-generate.");

    // 4. Kirim ke Frontend
    res.json({ qrCode: qrImage });
  } catch (err) {
    // MENANGKAP ERROR SPESIFIK KE LOG RENDER
    console.error("[FATAL ERROR] Gagal di /setup-mfa:", err.message);
    console.error(err.stack); // Menampilkan baris pasti yang error
    res
      .status(500)
      .json({ error: "Gagal membuat QR Code MFA: " + err.message });
  }
});

app.post("/api/auth/login", loginLimiter, async (req, res) => {
  const { username, password, totp_code } = req.body;

  try {
    // Ubah pencarian database ke username
    const userResult = await pool.query(
      "SELECT * FROM users WHERE username = $1",
      [username],
    );
    const user = userResult.rows[0];

    if (!user) {
      await pool.query(
        "INSERT INTO auth_logs (username, action) VALUES ($1, 'LOGIN_FAILED')",
        [username],
      );
      return res.status(401).json({ error: "Kredensial tidak valid" });
    }

    const validPass = await bcrypt.compare(password, user.password_hash);
    if (!validPass) {
      await pool.query(
        "INSERT INTO auth_logs (username, action) VALUES ($1, 'LOGIN_FAILED')",
        [username],
      );
      return res.status(401).json({ error: "Kredensial tidak valid" });
    }

    if (user.totp_secret) {
      // Verifikasi format otplib V13
      const verification = await verify({
        secret: user.totp_secret,
        token: totp_code,
      });

      if (!verification.valid) {
        await pool.query(
          "INSERT INTO auth_logs (, action) VALUES ($1, 'TOTP_FAILED')",
          [username],
        );
        return res.status(401).json({ error: "Kode MFA tidak valid" });
      }
    } else if (totp_code) {
      // If they provided a code but haven't set up MFA yet, allow standard pass-through for now
      // so they can log in and view the QR code in settings.
    }

    const accessToken = jwt.sign(
      { id: user.id, username: user.username },
      process.env.JWT_SECRET || "fallback_secret",
      { expiresIn: "1h" },
    );

    await pool.query(
      "INSERT INTO auth_logs (username, action) VALUES ($1, 'LOGIN_SUCCESS')",
      [username],
    );
    res.json({
      accessToken,
      message: "Login Berhasil",
      user: { username: user.username, name: user.full_name },
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Internal server error during login." });
  }
});

app.put("/api/auth/force-reset-password", async (req, res) => {
  // 1. Extract the JWT from the Authorization header
  const authHeader = req.headers.authorization;
  if (!authHeader)
    return res.status(401).json({ error: "Sesi tidak valid / Unauthorized" });

  const token = authHeader.split(" ")[1];

  try {
    // 2. Verify the token belongs to our system
    const decoded = jwt.verify(
      token,
      process.env.JWT_SECRET || "fallback_secret",
    );

    // 3. Extract the new password from the frontend request
    const { newPassword } = req.body;
    if (!newPassword || newPassword.length < 6) {
      return res.status(400).json({ error: "Password minimal 6 karakter." });
    }

    // 4. Hash the new password (10 rounds is the sweet spot for speed and security)
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(newPassword, salt);

    // 5. Push the new hash to the PostgreSQL database
    const result = await pool.query(
      "UPDATE users SET password_hash = $1, updated_at = CURRENT_TIMESTAMP WHERE username = $2 RETURNING username",
      [hashedPassword, decoded.username],
    );

    if (result.rowCount === 0) {
      return res
        .status(404)
        .json({ error: "User tidak ditemukan di database." });
    }

    res.json({ message: "Sandi berhasil diubah." });
  } catch (err) {
    console.error("Reset Password Error:", err);
    res
      .status(500)
      .json({ error: "Sesi kadaluarsa atau terjadi kesalahan server." });
  }
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
