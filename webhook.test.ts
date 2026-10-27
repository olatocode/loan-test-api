// npm i -D vitest supertest @types/supertest
// Run:  TEST_DATABASE_URL=postgres://... npx vitest run
// WARNING: the integration test TRUNCATEs payments and loans. Point it at a throwaway database.

import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import request from "supertest";
import crypto from "node:crypto";
import { Pool } from "pg";

const SECRET = "whsec_test_secret";

// The provider's test vector: exact bytes, single line.
const T = "1792800000";
const VECTOR_BODY =
  '{"event_id":"evt_1001","type":"payment.succeeded","loan_id":"LN-2041","amount":25000,"currency":"NGN","paid_at":"2026-10-23T09:15:00Z"}';
const VECTOR_SIG = "4351938d620d1c4eb2db79e390b5826d2b82e1e8cd9944671f0e3b60e9a6cdc1";

let mod: typeof import("./webhook");

beforeAll(async () => {
  // Env must be set before the module loads: it reads the secret at import time.
  process.env.WEBHOOK_SECRET = SECRET;
  process.env.DATABASE_URL = process.env.TEST_DATABASE_URL ?? "postgres://unused/unused";
  process.env.NODE_ENV = "test"; // stops webhook.ts from binding a port
  mod = await import("./webhook");
});

afterAll(async () => {
  await mod.pool.end();
});

// ---------------------------------------------------------------------------
// TEST 1: signature verification against the provider's test vector (unit)
// ---------------------------------------------------------------------------
describe("verifySignature", () => {
  it("accepts the provider's test vector", () => {
    expect(mod.verifySignature(T, Buffer.from(VECTOR_BODY), [VECTOR_SIG])).toBe(true);
  });

  it("rejects a body changed by a single character", () => {
    const tampered = VECTOR_BODY.replace('"amount":25000', '"amount":25001');
    expect(mod.verifySignature(T, Buffer.from(tampered), [VECTOR_SIG])).toBe(false);
  });

  it("rejects the same JSON re-serialised with different whitespace (raw bytes matter)", () => {
    const pretty = JSON.stringify(JSON.parse(VECTOR_BODY), null, 2);
    expect(mod.verifySignature(T, Buffer.from(pretty), [VECTOR_SIG])).toBe(false);
  });

  it("rejects a valid signature paired with a different timestamp", () => {
    expect(mod.verifySignature("1792800001", Buffer.from(VECTOR_BODY), [VECTOR_SIG])).toBe(false);
  });

  it("returns false (does not throw) for non-hex or wrong-length signatures", () => {
    for (const bad of ["", "abc", "zz".repeat(32), VECTOR_SIG.slice(0, 62), VECTOR_SIG + "00"]) {
      expect(mod.verifySignature(T, Buffer.from(VECTOR_BODY), [bad])).toBe(false);
    }
  });

  it("accepts if any one of several v1 values matches (secret rotation)", () => {
    const stale = "0".repeat(64);
    expect(mod.verifySignature(T, Buffer.from(VECTOR_BODY), [stale, VECTOR_SIG])).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// TEST 2: the same event_id arriving many times at the same instant (integration)
// ---------------------------------------------------------------------------
function sign(body: string, t = Math.floor(Date.now() / 1000)) {
  const v1 = crypto.createHmac("sha256", SECRET).update(`${t}.${body}`).digest("hex");
  return `t=${t},v1=${v1}`;
}

describe.skipIf(!process.env.TEST_DATABASE_URL)("concurrent duplicate events", () => {
  let db: Pool;

  beforeAll(() => {
    db = new Pool({ connectionString: process.env.TEST_DATABASE_URL });
  });
  afterAll(async () => {
    await db.end();
  });

  beforeEach(async () => {
    await db.query("TRUNCATE payments, loans RESTART IDENTITY CASCADE");
    await db.query(
      `INSERT INTO loans (id, customer_ref, currency, amount_due_minor)
       VALUES ('LN-2041', 'cust_test_1', 'NGN', 100000)`
    );
  });

  it("records the payment exactly once and returns 200 to every caller", async () => {
    const body = JSON.stringify({
      event_id: "evt_race_1",
      type: "payment.succeeded",
      loan_id: "LN-2041",
      amount: 25000,
      currency: "NGN",
      paid_at: "2026-10-23T09:15:00Z",
    });
    const header = sign(body);

    // Fire 10 identical deliveries at once.
    const responses = await Promise.all(
      Array.from({ length: 10 }, () =>
        request(mod.app)
          .post("/webhooks/payments")
          .set("Content-Type", "application/json")
          .set("X-Signature", header)
          .send(body)
      )
    );

    // Every caller is told "got it": duplicates are success, so the provider stops retrying.
    expect(responses.map((r) => r.status)).toEqual(Array(10).fill(200));

    // Exactly one payment row...
    const payments = await db.query("SELECT count(*)::int AS n FROM payments WHERE event_id = 'evt_race_1'");
    expect(payments.rows[0].n).toBe(1);

    // ...and the loan was credited once, not ten times.
    const loan = await db.query("SELECT amount_paid_minor, status FROM loans WHERE id = 'LN-2041'");
    expect(Number(loan.rows[0].amount_paid_minor)).toBe(25000);
    expect(loan.rows[0].status).toBe("active");
  });
});
