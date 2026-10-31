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
        license_key: licenseKey,
        increment_uses_count: increment ? "true" : "false",
      }),
    });
  } catch {
    return { state: "error" };
  }

  let data = null;
  try {
    data = await res.json();
  } catch {
    /* not JSON */
  }

  if (res.status === 404 || (data && data.success === false)) return { state: "invalid" };
  if (!res.ok || !data || data.success !== true) return { state: "error" };

  const p = data.purchase || {};
  const revoked =
    p.refunded === true ||
    p.chargebacked === true ||
    (p.disputed === true && p.dispute_won !== true) ||
    Boolean(p.subscription_cancelled_at) ||
    Boolean(p.subscription_ended_at) ||
    Boolean(p.subscription_failed_at);
  if (revoked) return { state: "revoked" };

  return { state: "valid", uses: Number(data.uses) || 0 };
}

export default async (req) => {
  if (req.method !== "POST") return json({ ok: false, reason: "method" }, 405);

  // Only accept requests from this same site.
  const origin = req.headers.get("origin");
  if (origin) {
    try {
      if (new URL(origin).host !== new URL(req.url).host) return json({ ok: false, reason: "origin" }, 403);
    } catch {
      return json({ ok: false, reason: "origin" }, 403);
    }
  }

  const productId = process.env.GUMROAD_PRODUCT_ID;
  const secret = process.env.TOKEN_SECRET;
  if (!productId || !secret || secret.length < 32) {
    console.error("verify: GUMROAD_PRODUCT_ID or TOKEN_SECRET is missing or too short");
    return json({ ok: false, reason: "unavailable" }, 503);
  }
  const maxUses = num(process.env.MAX_USES, 5);
  const recheckMs = num(process.env.RECHECK_HOURS, 24) * 60 * 60 * 1000;

  let body;
  try {
    body = await req.json();
  } catch {
    return json({ ok: false, reason: "bad_request" }, 400);
  }
  const now = Date.now();

  // ---- first-time unlock with a license key ----
  if (body && body.action === "activate") {
    const key = typeof body.license_key === "string" ? body.license_key.trim() : "";
    if (key.length < 8 || key.length > 100) return json({ ok: false, reason: "invalid" });

    const result = await checkWithGumroad(key, productId, true);
    if (result.state === "error") return json({ ok: false, reason: "unavailable" }, 503);
    if (result.state === "invalid") return json({ ok: false, reason: "invalid" });
    if (result.state === "revoked") return json({ ok: false, reason: "revoked" });
    if (maxUses > 0 && result.uses > maxUses) return json({ ok: false, reason: "limit" });

    return json({ ok: true, token: seal({ k: key, v: now }, secret) });
  }

  // ---- returning customer with a saved token ----
  if (body && body.action === "check") {
    const payload = open(body.token, secret);
    if (!payload || payload.v > now + 60_000 || now - payload.v > MAX_IDLE_MS) {
      return json({ ok: false, reason: "invalid" });
    }

    // Recently verified: no need to ask Gumroad again.
    if (now - payload.v < recheckMs) return json({ ok: true });

    // Re-check with Gumroad so refunded or revoked purchases lose access.
    const result = await checkWithGumroad(payload.k, productId, false);
    if (result.state === "error") return json({ ok: false, reason: "unavailable" }, 503);
    if (result.state === "invalid") return json({ ok: false, reason: "invalid" });
    if (result.state === "revoked") return json({ ok: false, reason: "revoked" });

    return json({ ok: true, token: seal({ k: payload.k, v: now }, secret) });
  }

  return json({ ok: false, reason: "bad_request" }, 400);
};

export const config = { path: "/api/verify" };
