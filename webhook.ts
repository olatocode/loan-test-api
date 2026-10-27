import "dotenv/config";
import express from "express";
import crypto from "node:crypto";
import { Pool } from "pg";
import { z } from "zod";

const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET;
if (!WEBHOOK_SECRET) throw new Error("WEBHOOK_SECRET is not set"); // fail at boot, not per-request
const TOLERANCE_SECONDS = 5 * 60;

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

// ---------------------------------------------------------------------------
// 6. Logging: allowlist of fields. There is deliberately no way to pass the body,
//    headers, or secret in here. event_id is logged only AFTER the signature has
//    been verified, because before that it is attacker-controlled input.
// ---------------------------------------------------------------------------
function log(
  level: "info" | "warn" | "error",
  msg: string,
  fields: { event_id?: string; type?: string; outcome?: string; code?: string } = {}
) {
  console.log(JSON.stringify({ ts: new Date().toISOString(), level, msg, ...fields }));
}

// ---------------------------------------------------------------------------
// 1. Signature verification
// ---------------------------------------------------------------------------
function parseSignatureHeader(header: string | undefined): { t: string; v1: string[] } | null {
  if (!header) return null;
  let t: string | undefined;
  const v1: string[] = []; // accept several v1= values, which makes secret rotation painless
  for (const part of header.split(",")) {
    const i = part.indexOf("=");
    if (i < 0) continue;
    const key = part.slice(0, i).trim();
    const value = part.slice(i + 1).trim();
    if (key === "t") t = value;
    else if (key === "v1") v1.push(value);
  }
  if (!t || !/^\d{1,12}$/.test(t) || v1.length === 0) return null;
  return { t, v1 };
}

export function verifySignature(t: string, rawBody: Buffer, candidates: string[]): boolean {
  // HMAC-SHA256(secret, t + "." + rawBody), computed over the exact bytes received.
  const expected = crypto
    .createHmac("sha256", WEBHOOK_SECRET!)
    .update(`${t}.`)
    .update(rawBody)
    .digest(); // 32-byte Buffer
  return candidates.some((c) => {
    if (!/^[0-9a-f]{64}$/i.test(c)) return false; // timingSafeEqual throws on length mismatch
    return crypto.timingSafeEqual(expected, Buffer.from(c, "hex"));
  });
}

// ---------------------------------------------------------------------------
// Payload validation (only for the event type we handle)
// ---------------------------------------------------------------------------
const Envelope = z.object({ event_id: z.string().min(1).max(128), type: z.string() });

const PaymentSucceeded = z.object({
  event_id: z.string().min(1).max(128),
  type: z.literal("payment.succeeded"),
  loan_id: z.string().min(1).max(64),
  amount: z.number().int().positive().max(Number.MAX_SAFE_INTEGER), // minor units
  currency: z.string().length(3),
  paid_at: z.string().datetime(),
});
type PaymentEvent = z.infer<typeof PaymentSucceeded>;

// ---------------------------------------------------------------------------
// 3. Exactly-once recording. One transaction: insert payment + bump loan.
// ---------------------------------------------------------------------------
type Outcome = "recorded" | "duplicate" | "unknown_loan" | "currency_mismatch";

async function recordPayment(e: PaymentEvent): Promise<Outcome> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    // The UNIQUE(event_id) index is the lock. If two requests race with the same
    // event_id, the second blocks here until the first commits/rolls back, then
    // either inserts nothing (duplicate) or, if the first rolled back, proceeds.
    const ins = await client.query(
      `INSERT INTO payments (event_id, loan_id, amount_minor, currency, paid_at)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (event_id) DO NOTHING
       RETURNING id`,
      [e.event_id, e.loan_id, e.amount, e.currency, e.paid_at]
    );
    if (ins.rowCount === 0) {
      await client.query("ROLLBACK");
      return "duplicate"; // already recorded: a success from the provider's point of view
    }

    // Atomic increment (no read-modify-write), so addition is commutative:
    // out-of-order and delayed events produce the same final balance.
    const upd = await client.query(
      `UPDATE loans
          SET amount_paid_minor = amount_paid_minor + $2,
              status = CASE WHEN amount_paid_minor + $2 >= amount_due_minor
                            THEN 'paid' ELSE status END
        WHERE id = $1 AND currency = $3`,
      [e.loan_id, e.amount, e.currency]
    );
    if (upd.rowCount === 0) {
      // Loan exists (FK passed) but currency differs. Roll back the payment insert too.
      await client.query("ROLLBACK");
      return "currency_mismatch";
    }

    await client.query("COMMIT");
    return "recorded";
  } catch (err: any) {
    await client.query("ROLLBACK").catch(() => {});
    if (err?.code === "23503") return "unknown_loan"; // FK violation: no such loan
    throw err; // anything else is unexpected -> caller returns 500 so the provider retries
  } finally {
    client.release();
  }
}

// ---------------------------------------------------------------------------
// The endpoint
// ---------------------------------------------------------------------------
const app = express();

// IMPORTANT: raw body for this route. If a JSON parser runs first, re-serialising
// the object changes the bytes and every signature check fails.
app.post(
  "/webhooks/payments",
  express.raw({ type: () => true, limit: "100kb" }),
  async (req, res) => {
    const raw = req.body;
    if (!Buffer.isBuffer(raw) || raw.length === 0) {
      log("warn", "empty body rejected");
      return res.status(400).end();
    }

    // 1. Verify BEFORE parsing or trusting anything. Same 401 for missing/malformed/wrong.
    const sig = parseSignatureHeader(req.header("X-Signature"));
    if (!sig || !verifySignature(sig.t, raw, sig.v1)) {
      log("warn", "signature rejected");
      return res.status(401).end(); // 4xx: retrying the same bad request will never help
    }

    // 2. Replay window. t is only trustworthy now that it is covered by a valid signature.
    const ageSeconds = Math.abs(Date.now() / 1000 - Number(sig.t)); // abs() also rejects far-future
    if (ageSeconds > TOLERANCE_SECONDS) {
      log("warn", "stale timestamp rejected");
      return res.status(400).end();
    }

    // Parse (signature is valid, so a parse failure is a provider bug: permanent, don't retry)
    let json: unknown;
    try {
      json = JSON.parse(raw.toString("utf8"));
    } catch {
      log("warn", "invalid json");
      return res.status(400).end();
    }

    const env = Envelope.safeParse(json);
    if (!env.success) {
      log("warn", "invalid envelope");
      return res.status(400).end();
    }

    // 5. Unknown types: acknowledge with 200 so the provider doesn't retry or disable us.
    if (env.data.type !== "payment.succeeded") {
      log("info", "ignored event type", { event_id: env.data.event_id, type: env.data.type });
      return res.status(200).end();
    }

    const parsed = PaymentSucceeded.safeParse(json);
    if (!parsed.success) {
      log("warn", "invalid payment payload", { event_id: env.data.event_id }); // no zod issues: they can echo values
      return res.status(400).end();
    }

    // 3 + 4. Record, then map the outcome to a status code.
    try {
      const outcome = await recordPayment(parsed.data);
      log("info", "payment event handled", { event_id: parsed.data.event_id, outcome });

      switch (outcome) {
        case "recorded":
        case "duplicate":
          return res.status(200).end(); // duplicates are success, not errors
        case "currency_mismatch":
          return res.status(422).end(); // permanent, needs a human; alert on this log line
        case "unknown_loan":
          return res.status(503).end(); // maybe transient (lag/ordering): let the provider retry
      }
    } catch (err: any) {
      log("error", "db failure", { event_id: parsed.data.event_id, code: err?.code }); // never log err.message/query params
      return res.status(500).end(); // transient: provider should retry; idempotency makes that safe
    }
  }
);

export { app, pool };

if (process.env.NODE_ENV !== "test") {
  const port = Number(process.env.PORT ?? 3000);
  app.listen(port, () => {
    log("info", `Server listening on http://localhost:${port}`);
  });
}
