import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import crypto from "crypto";
import fs from "fs";
import dotenv from "dotenv";
import nodemailer from "nodemailer";
import bcrypt from "bcryptjs";
import speakeasy from "speakeasy";
import qrcode from "qrcode";
import { Pool } from "pg";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;
const BASE_URL = process.env.BASE_URL || process.env.RENDER_EXTERNAL_URL || `http://localhost:${PORT}`;
const DATABASE_URL = process.env.DATABASE_URL;
const USE_DB = Boolean(DATABASE_URL);

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

app.use(express.json());
app.use(express.static(__dirname));

// ----------------------- USERS STORAGE -----------------------
const users = new Map(); // email -> { nick, email, passwordHash, totpSecret, createdAt }
const pending = new Map(); // token -> { nick, email, passwordHash, createdAt }
const resetTokens = new Map(); // token -> { email, createdAt }

const dbSsl = process.env.DATABASE_SSL === "true" || process.env.NODE_ENV === "production";
const pool = USE_DB
  ? new Pool({
      connectionString: DATABASE_URL,
      ssl: dbSsl ? { rejectUnauthorized: false } : false,
    })
  : null;

async function initDb() {
  if (!USE_DB) return;
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      email TEXT PRIMARY KEY,
      nick TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      totp_secret TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS pending_verifications (
      token TEXT PRIMARY KEY,
      nick TEXT NOT NULL,
      email TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS reset_tokens (
      token TEXT PRIMARY KEY,
      email TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);
}

initDb().catch((error) => {
  console.error("Błąd inicjalizacji bazy danych:", error?.message || error);
});

async function getUserByEmail(email) {
  if (!USE_DB) return users.get(email) || null;
  const { rows } = await pool.query(
    "SELECT email, nick, password_hash, totp_secret, created_at FROM users WHERE email = $1",
    [email]
  );
  if (!rows[0]) return null;
  return {
    email: rows[0].email,
    nick: rows[0].nick,
    passwordHash: rows[0].password_hash,
    totpSecret: rows[0].totp_secret,
    createdAt: rows[0].created_at,
  };
}

async function saveUser({ email, nick, passwordHash, totpSecret }) {
  if (!USE_DB) {
    users.set(email, { email, nick, passwordHash, totpSecret, createdAt: Date.now() });
    return;
  }
  await pool.query(
    `
      INSERT INTO users (email, nick, password_hash, totp_secret)
      VALUES ($1, $2, $3, $4)
      ON CONFLICT (email)
      DO UPDATE SET nick = EXCLUDED.nick, password_hash = EXCLUDED.password_hash, totp_secret = EXCLUDED.totp_secret
    `,
    [email, nick, passwordHash, totpSecret]
  );
}

async function createPendingVerification({ token, nick, email, passwordHash }) {
  if (!USE_DB) {
    pending.set(token, { nick, email, passwordHash, createdAt: Date.now() });
    return;
  }
  await pool.query(
    "INSERT INTO pending_verifications (token, nick, email, password_hash) VALUES ($1, $2, $3, $4)",
    [token, nick, email, passwordHash]
  );
}

async function getPendingVerification(token) {
  if (!USE_DB) return pending.get(token) || null;
  const { rows } = await pool.query(
    "SELECT token, nick, email, password_hash, created_at FROM pending_verifications WHERE token = $1",
    [token]
  );
  if (!rows[0]) return null;
  return {
    token: rows[0].token,
    nick: rows[0].nick,
    email: rows[0].email,
    passwordHash: rows[0].password_hash,
    createdAt: rows[0].created_at,
  };
}

async function deletePendingVerification(token) {
  if (!USE_DB) {
    pending.delete(token);
    return;
  }
  await pool.query("DELETE FROM pending_verifications WHERE token = $1", [token]);
}

async function createResetToken({ token, email }) {
  if (!USE_DB) {
    resetTokens.set(token, { email, createdAt: Date.now() });
    return;
  }
  await pool.query("INSERT INTO reset_tokens (token, email) VALUES ($1, $2)", [token, email]);
}

async function getResetToken(token) {
  if (!USE_DB) return resetTokens.get(token) || null;
  const { rows } = await pool.query(
    "SELECT token, email, created_at FROM reset_tokens WHERE token = $1",
    [token]
  );
  if (!rows[0]) return null;
  return { token: rows[0].token, email: rows[0].email, createdAt: rows[0].created_at };
}

async function deleteResetToken(token) {
  if (!USE_DB) {
    resetTokens.delete(token);
    return;
  }
  await pool.query("DELETE FROM reset_tokens WHERE token = $1", [token]);
}

async function updateUserPassword(email, passwordHash) {
  if (!USE_DB) {
    const user = users.get(email);
    if (user) users.set(email, { ...user, passwordHash });
    return;
  }
  await pool.query("UPDATE users SET password_hash = $1 WHERE email = $2", [passwordHash, email]);
}

function makeTransporter() {
  if (!process.env.SMTP_HOST || !process.env.SMTP_USER || !process.env.SMTP_PASS) return null;
  return nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT || 587),
    secure: process.env.SMTP_SECURE === "true",
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
  });
}

const transporter = makeTransporter();
const LOG_FILE = path.join(__dirname, "logins.log");

function logLogin({ email, nick }) {
  const line = `${new Date().toISOString()} | ${email} | ${nick}\n`;
  fs.appendFile(LOG_FILE, line, () => {});
}

function sendVerificationEmail({ email, token }) {
  const verifyLink = `${BASE_URL}/verify?token=${token}`;
  const from = process.env.MAIL_FROM || "Nasioneria <no-reply@nasioneria.local>";
  if (!transporter) {
    console.log("[DEV] Brak konfiguracji SMTP. Link weryfikacyjny:", verifyLink);
    return Promise.resolve();
  }
  return transporter.sendMail({
    from,
    to: email,
    subject: "Potwierdź rejestrację — Nasioneria",
    html: `<p>Cześć!</p><p>Kliknij w link, aby potwierdzić rejestrację:</p><p><a href="${verifyLink}">${verifyLink}</a></p><p>Jeśli to nie Ty, zignoruj tę wiadomość.</p>`,
  });
}

function sendResetEmail({ email, token }) {
  const resetLink = `${BASE_URL}/reset.html?token=${token}`;
  const from = process.env.MAIL_FROM || "Nasioneria <no-reply@nasioneria.local>";
  if (!transporter) {
    console.log("[DEV] Brak konfiguracji SMTP. Link resetu:", resetLink);
    return Promise.resolve();
  }
  return transporter.sendMail({
    from,
    to: email,
    subject: "Reset hasła — Nasioneria",
    html: `<p>Cześć!</p><p>Kliknij w link, aby zresetować hasło:</p><p><a href="${resetLink}">${resetLink}</a></p><p>Jeśli to nie Ty, zignoruj tę wiadomość.</p>`,
  });
}

// ----------------------- REGISTER -----------------------
app.post("/api/register", async (req, res) => {
  try {
    const { nick, email, password, confirmHuman } = req.body || {};

    if (!nick || !email || !password) return res.status(400).json({ message: "Uzupełnij wszystkie pola." });
    if (!confirmHuman) return res.status(400).json({ message: "Potwierdź, że nie jesteś botem." });

    const existing = await getUserByEmail(email);
    if (existing) return res.status(400).json({ message: "Konto z tym e‑mailem już istnieje." });

    const passwordHash = await bcrypt.hash(password, 10);
    const token = crypto.randomBytes(24).toString("hex");

    await createPendingVerification({ token, nick, email, passwordHash });

    try {
      await sendVerificationEmail({ email, token });
      return res.json({ message: "Wysłano link weryfikacyjny na e‑mail." });
    } catch (error) {
      await deletePendingVerification(token);
      console.error("Błąd wysyłki e‑mail:", error?.message || error);
      return res.status(500).json({ message: "Nie udało się wysłać maila. Sprawdź SMTP w .env." });
    }
  } catch (error) {
    console.error("Błąd rejestracji:", error?.message || error);
    return res.status(500).json({ message: "Błąd serwera podczas rejestracji." });
  }
});

// ----------------------- VERIFY -----------------------
app.get("/verify", async (req, res) => {
  const { token } = req.query;
  const record = await getPendingVerification(token);

  if (!record) return res.status(400).send("Nieprawidłowy lub wygasły link.");

  await deletePendingVerification(token);

  // ----------------------- GENERATE 2FA SECRET -----------------------
  const totpSecret = speakeasy.generateSecret({ name: `Nasioneria (${record.nick})` });
  await saveUser({
    email: record.email,
    nick: record.nick,
    passwordHash: record.passwordHash,
    totpSecret: totpSecret.base32,
  });

  // Generate QR code data URL
  const otpAuthUrl = totpSecret.otpauth_url;
  const qrCodeDataURL = await qrcode.toDataURL(otpAuthUrl);

  return res.send(`
    <html lang="pl">
      <head>
        <meta charset="utf-8" />
        <title>Weryfikacja zakończona</title>
        <style>
          body { font-family: system-ui, sans-serif; background:#0f1315; color:#e9eef2; display:flex; align-items:center; justify-content:center; height:100vh; margin:0; }
          .card { background:#151b1f; border:1px solid #222a31; border-radius:16px; padding:24px; text-align:center; max-width:420px; }
          a { color:#44d17a; }
        </style>
      </head>
      <body>
        <div class="card">
          <h2>Konto potwierdzone</h2>
          <p>Twoje konto zostało utworzone.</p>
          <p>Włącz 2FA skanując poniższy QR kod w aplikacji Authenticator:</p>
          <img src="${qrCodeDataURL}" alt="QR kod 2FA" />
          <p><strong>Albo użyj kodu: ${totpSecret.base32}</strong></p>
          <p><a href="/">Wróć na stronę</a></p>
        </div>
      </body>
    </html>
  `);
});

// ----------------------- LOGIN -----------------------
app.post("/api/login", async (req, res) => {
  const { email, password, token2FA } = req.body || {};
  if (!email || !password) return res.status(400).json({ message: "Podaj email i hasło." });

  const user = await getUserByEmail(email);
  if (!user) return res.status(401).json({ message: "Nieprawidłowe dane logowania lub brak weryfikacji." });

  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(401).json({ message: "Nieprawidłowe dane logowania." });

  // ----------------------- VERIFY 2FA -----------------------
  if (!token2FA) return res.status(400).json({ message: "Wymagany kod 2FA." });

  const verified = speakeasy.totp.verify({
    secret: user.totpSecret,
    encoding: "base32",
    token: token2FA,
  });
  if (!verified) return res.status(401).json({ message: "Nieprawidłowy kod 2FA." });

  logLogin({ email, nick: user.nick });
  return res.json({ message: `Zalogowano jako ${user.nick}.`, nick: user.nick });
});

// ----------------------- PASSWORD RESET -----------------------
app.post("/api/forgot", async (req, res) => {
  const { email } = req.body || {};
  if (!email) return res.status(400).json({ message: "Podaj email." });

  const user = await getUserByEmail(email);
  if (!user) return res.json({ message: "Jeśli konto istnieje, wysłaliśmy link resetu." });

  const token = crypto.randomBytes(24).toString("hex");
  await createResetToken({ token, email });

  try {
    await sendResetEmail({ email, token });
    return res.json({ message: "Jeśli konto istnieje, wysłaliśmy link resetu." });
  } catch (error) {
    await deleteResetToken(token);
    console.error("Błąd wysyłki e‑mail (reset):", error?.message || error);
    return res.status(500).json({ message: "Nie udało się wysłać maila. Sprawdź SMTP w .env." });
  }
});

app.post("/api/reset", async (req, res) => {
  const { token, password } = req.body || {};
  if (!token || !password) return res.status(400).json({ message: "Nieprawidłowe dane." });

  const record = await getResetToken(token);
  if (!record) return res.status(400).json({ message: "Nieprawidłowy lub wygasły link." });

  const user = await getUserByEmail(record.email);
  if (!user) {
    await deleteResetToken(token);
    return res.status(400).json({ message: "Nieprawidłowy lub wygasły link." });
  }

  const passwordHash = await bcrypt.hash(password, 10);
  await updateUserPassword(record.email, passwordHash);
  await deleteResetToken(token);

  return res.json({ message: "Hasło zostało zmienione." });
});

// ----------------------- START SERVER -----------------------
app.listen(PORT, () => console.log(`Serwer działa: ${BASE_URL}`));