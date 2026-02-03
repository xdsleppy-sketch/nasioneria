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

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

app.use(express.json());
app.use(express.static(__dirname));

// ----------------------- USERS STORAGE -----------------------
const users = new Map(); // email -> { nick, email, passwordHash, totpSecret, createdAt }
const pending = new Map(); // token -> { nick, email, passwordHash, createdAt }
const resetTokens = new Map(); // token -> { email, createdAt }

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
  const { nick, email, password, confirmHuman } = req.body || {};

  if (!nick || !email || !password) return res.status(400).json({ message: "Uzupełnij wszystkie pola." });
  if (!confirmHuman) return res.status(400).json({ message: "Potwierdź, że nie jesteś botem." });
  if (users.has(email)) return res.status(400).json({ message: "Konto z tym e‑mailem już istnieje." });

  const passwordHash = await bcrypt.hash(password, 10);
  const token = crypto.randomBytes(24).toString("hex");

  pending.set(token, {
    nick,
    email,
    passwordHash,
    createdAt: Date.now(),
  });

  try {
    await sendVerificationEmail({ email, token });
    return res.json({ message: "Wysłano link weryfikacyjny na e‑mail." });
  } catch (error) {
    pending.delete(token);
    console.error("Błąd wysyłki e‑mail:", error?.message || error);
    return res.status(500).json({ message: "Nie udało się wysłać maila. Sprawdź SMTP w .env." });
  }
});

// ----------------------- VERIFY -----------------------
app.get("/verify", async (req, res) => {
  const { token } = req.query;
  const record = pending.get(token);

  if (!record) return res.status(400).send("Nieprawidłowy lub wygasły link.");

  pending.delete(token);

  // ----------------------- GENERATE 2FA SECRET -----------------------
  const totpSecret = speakeasy.generateSecret({ name: `Nasioneria (${record.nick})` });
  users.set(record.email, { ...record, totpSecret: totpSecret.base32 });

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

  const user = users.get(email);
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

  const user = users.get(email);
  if (!user) return res.json({ message: "Jeśli konto istnieje, wysłaliśmy link resetu." });

  const token = crypto.randomBytes(24).toString("hex");
  resetTokens.set(token, { email, createdAt: Date.now() });

  try {
    await sendResetEmail({ email, token });
    return res.json({ message: "Jeśli konto istnieje, wysłaliśmy link resetu." });
  } catch (error) {
    resetTokens.delete(token);
    console.error("Błąd wysyłki e‑mail (reset):", error?.message || error);
    return res.status(500).json({ message: "Nie udało się wysłać maila. Sprawdź SMTP w .env." });
  }
});

app.post("/api/reset", async (req, res) => {
  const { token, password } = req.body || {};
  if (!token || !password) return res.status(400).json({ message: "Nieprawidłowe dane." });

  const record = resetTokens.get(token);
  if (!record) return res.status(400).json({ message: "Nieprawidłowy lub wygasły link." });

  const user = users.get(record.email);
  if (!user) {
    resetTokens.delete(token);
    return res.status(400).json({ message: "Nieprawidłowy lub wygasły link." });
  }

  const passwordHash = await bcrypt.hash(password, 10);
  users.set(record.email, { ...user, passwordHash });
  resetTokens.delete(token);

  return res.json({ message: "Hasło zostało zmienione." });
});

// ----------------------- START SERVER -----------------------
app.listen(PORT, () => console.log(`Serwer działa: ${BASE_URL}`));