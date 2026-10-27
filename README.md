# Loan Payment Webhook API

A robust, idempotent payment webhook service built with Node.js, Express, TypeScript, and PostgreSQL. It safely verifies, validates, and records payment events against loans with strict concurrency controls and replay protection.

---

## Features

- **HMAC-SHA256 Signature Verification**: Computes and checks signatures over exact raw byte payloads (`express.raw`). Supports smooth secret rotation with multiple `v1` candidate signatures.
- **Replay Protection**: Enforces timestamp freshness (`t` parameter in `X-Signature`) within a 5-minute tolerance window.
- **Strict Payload Validation**: Zod-based schema parsing for event envelopes and `payment.succeeded` payloads.
- **Idempotency & Exactly-Once Processing**:
  - Uses `UNIQUE(event_id)` constraint in PostgreSQL as a concurrency lock.
  - Returns `200 OK` for duplicate events to acknowledge the provider without double-crediting.
  - Atomic commutative balance increments (`amount_paid_minor = amount_paid_minor + $2`), preventing race conditions.
- **Security-First Logging**: Strict allowlist of logged fields. Payloads and headers are never dumped, preventing leakages of secrets or unverified input.
- **Comprehensive Test Suite**: Unit and integration tests covering signature validation, payload tampering, whitespace invariance, timestamp verification, and concurrent deliveries.

---

## Architecture & Data Model

The database schema ([schema.sql](file:///c:/Users/olatoCode/Desktop/loan-test-api/schema.sql)) consists of two tables:

1. **`loans`**:
   - `id`: Unique loan identifier (e.g., `LN-2041`).
   - `customer_ref`: Opaque reference identifier.
   - `currency`: 3-character ISO currency code (e.g., `NGN`).
   - `amount_due_minor`: Total expected amount in minor units (e.g., cents/kobo).
   - `amount_paid_minor`: Cumulative amount paid so far.
   - `status`: `'active'` or `'paid'`.
2. **`payments`**:
   - `event_id`: Unique identifier from the webhook provider.
   - `loan_id`: Foreign key reference to `loans(id)`.
   - `amount_minor`: Payment amount in minor currency units.
   - `paid_at`: Event timestamp from provider.
   - `received_at`: Local ingestion timestamp.

---

## Getting Started

### Prerequisites

- **Node.js** (v20+ recommended)
- **PostgreSQL** (for persistence and integration tests)

### Installation

Clone the repository and install dependencies:

```bash
npm install
```

### Environment Configuration

Configure your environment variables in `.env` (or set them in your environment):

```env
# Secret key shared with the webhook provider
WEBHOOK_SECRET=whsec_test_secret

# PostgreSQL connection string
DATABASE_URL=postgresql://postgres:postgres@localhost:5432/loan_db

# Server port (default: 3000)
PORT=3000
```

### Database Initialization

To set up the tables and schema in your PostgreSQL database:

```bash
psql -d loan_db -f schema.sql
```

---

## Running the Application

### Development Mode (with hot reload)

```bash
npm run dev
```

### Production Mode

```bash
npm start
```

---

## API Reference

### Webhook Ingestion

- **Endpoint**: `POST /webhooks/payments`
- **Content-Type**: `application/json`
- **Headers**:
  - `X-Signature`: Formatted as `t=<timestamp>,v1=<signature>[,v1=<rotated_signature>]`

#### Example Request

```http
POST /webhooks/payments HTTP/1.1
Host: localhost:3000
Content-Type: application/json
X-Signature: t=1792800000,v1=4351938d620d1c4eb2db79e390b5826d2b82e1e8cd9944671f0e3b60e9a6cdc1

{
  "event_id": "evt_1001",
  "type": "payment.succeeded",
  "loan_id": "LN-2041",
  "amount": 25000,
  "currency": "NGN",
  "paid_at": "2026-10-23T09:15:00Z"
}
```

#### Status Codes

| Status Code | Reason | Action for Webhook Provider |
| :--- | :--- | :--- |
| `200 OK` | Payment recorded or duplicate acknowledged | Do not retry |
| `400 Bad Request` | Empty body, invalid JSON, or schema mismatch | Do not retry (permanent error) |
| `401 Unauthorized`| Missing, malformed, or invalid signature | Do not retry |
| `422 Unprocessable`| Loan currency mismatch | Requires human intervention |
| `503 Service Unavailable`| Unknown loan (e.g., race condition/replication lag) | Retry request |
| `500 Internal Error`| Database/transient system failure | Retry request |

---

## Testing

Run unit tests:

```bash
npm test
```

Run tests including concurrency integration tests (requires a test PostgreSQL instance):

```bash
TEST_DATABASE_URL=postgres://postgres:postgres@localhost:5432/loan_test_db npm test
```

---

## Project Structure

```text
├── schema.sql          # PostgreSQL schema and indexes
├── webhook.ts          # Main Express webhook endpoint & business logic
├── webhook.test.ts     # Unit and concurrency integration tests
├── tsconfig.json       # TypeScript configuration
├── package.json        # Project metadata, scripts, and dependencies
└── .env                # Local environment variables
```
