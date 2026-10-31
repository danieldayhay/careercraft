// CareerCraft license verification (Netlify Function, served at /api/verify).
//
// Required environment variables (set in Netlify, never in the website code):
//   GUMROAD_PRODUCT_ID  your Gumroad product ID
//   TOKEN_SECRET        a long random string (32+ characters) used to encrypt access tokens
// Optional:
//   MAX_USES            how many times one license key may be activated (default 5)
//   RECHECK_HOURS       how often a saved login is re-checked with Gumroad (default 24)

import crypto from "node:crypto";

const GUMROAD_VERIFY_URL = "https://api.gumroad.com/v2/licenses/verify";
const MAX_IDLE_MS = 90 * 24 * 60 * 60 * 1000; // ask for the key again after 90 days without a successful check

const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
  });

const num = (value, fallback) => {
  const n = Number(value);
  return value !== undefined && value !== "" && Number.isFinite(n) && n >= 0 ? n : fallback;
};

// ---- encrypted, tamper-proof tokens (AES-256-GCM) ----
const secretKey = (secret) => crypto.createHash("sha256").update(secret).digest();

function seal(payload, secret) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", secretKey(secret), iv);
  const data = Buffer.concat([cipher.update(JSON.stringify(payload), "utf8"), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), data]).toString("base64url");
}

function open(token, secret) {
  try {
    const raw = Buffer.from(String(token), "base64url");
    if (raw.length < 29) return null;
    const decipher = crypto.createDecipheriv("aes-256-gcm", secretKey(secret), raw.subarray(0, 12));
    decipher.setAuthTag(raw.subarray(12, 28));
    const text = Buffer.concat([decipher.update(raw.subarray(28)), decipher.final()]).toString("utf8");
    const payload = JSON.parse(text);
    return payload && typeof payload.k === "string" && typeof payload.v === "number" ? payload : null;
  } catch {
    return null;
  }
}

// ---- Gumroad check ----
// Returns { state: "valid" | "invalid" | "revoked" | "error", uses }
async function checkWithGumroad(licenseKey, productId, increment) {
  let res;
  try {
    res = await fetch(GUMROAD_VERIFY_URL, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        product_id: productId,
