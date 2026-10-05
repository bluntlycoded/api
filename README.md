# FraudShield Authenticator API

Backend for an authenticator app: stores TOTP secrets per user, generates codes, and
protects sign-in with device trust, per-login risk scoring, impossible-travel checks
and number-matched approval.

Node 20+, Express, MongoDB (Mongoose), Socket.IO.

## Setup

```bash
npm install
cp .env.example .env     # then fill in MONGO_URI, JWT_SECRET, ENCRYPTION_KEY
npm run dev              # or: npm start
npm test
```

Generate secrets with `openssl rand -hex 32`. Keep `ENCRYPTION_KEY` safe: authenticator
secrets are encrypted with it (AES-256-GCM) and cannot be recovered without it.

If you already have users with plaintext secrets, run `npm run migrate:encrypt` once.

## How login works

1. `POST /api/auth/login` with `email`, `password`, `deviceId` (a random 16+ character
   secret the app generates once and keeps), optional `deviceName`, and `totp` if the
   account has two-factor enabled.
2. The server scores the attempt (see `config/risk.js`):

   | Signal | Points |
   |---|---|
   | New device | 40 |
   | Unrecognized website origin | 40 |
   | Impossible travel (over 900 km/h from the last login) | 60 |
   | New country | 25 |
   | 3+ failed attempts just before | 20 |
   | Odd hour (0-5 local, unless usual for the user) | 15 |
   | New IP | 10 |

3. Below 40 the response is `200 {token}`. At 40 or more it is
   `202 {challengeId, pollSecret, displayNumber}`: show `displayNumber` on the login
   screen. A trusted device receives the request (Socket.IO `approval_request`, or
   `GET /api/approval/pending`) showing site, IP, location and reasons, with three
   numbers to choose from. Picking the right one approves it.
4. The login screen learns the result from Socket.IO (`watch`) or by polling
   `POST /api/approval/:id/status`, then calls `POST /api/auth/login/complete` to get
   its token. Tokens are single use and tied to the requesting device.

The first device an account logs in from is trusted automatically.

## Endpoints

All `/api` routes except those marked *public* need `Authorization: Bearer <token>`.
Routes marked *trusted* also need a session from a trusted device.

| Method and path | Purpose |
|---|---|
| `POST /api/auth/register` *public* | Create account; registering device becomes trusted |
| `POST /api/auth/login` *public* | Log in (see above) |
| `POST /api/auth/login/complete` *public* | Exchange an approved challenge for a token |
| `POST /api/auth/forgot-password` *public* | Email a reset link (same reply for unknown emails) |
| `POST /api/auth/reset-password` *public* | Set a new password with the emailed token |
| `POST /api/addapp` | Save an authenticator entry (`appName`, base32 `secretKey`) |
| `GET /api/addapp` | List saved entries |
| `GET /api/addapp/:appId/otp` | Current code for an entry |
| `DELETE /api/addapp/:appId` | Delete an entry |
| `POST /api/totp/setup` *trusted* | Start two-factor setup; returns secret and QR code |
| `POST /api/totp/enable` *trusted* | Confirm with a code to switch it on |
| `POST /api/totp/disable` *trusted* | Needs password and a current code |
| `GET /api/approval/pending` *trusted* | Open login requests |
| `POST /api/approval/:id/respond` *trusted* | `{action: "approve", choice, trustDevice?}` or `{action: "deny"}` |
| `POST /api/approval/:id/status` *public* | Poll a challenge with its `pollSecret` |
| `GET /api/devices` | Devices on the account |
| `DELETE /api/devices/:id` *trusted* | Revoke a device |
| `GET /api/security/logins` | Recent login attempts with risk score and reasons |
| `GET /api/security/audit` | Password resets, 2FA changes, approvals, device removals |
| `POST /api/blockchain/create-wallet` | New Solana keypair (private key returned once, not stored) |
| `POST /api/blockchain/check-balance` | Devnet balance for a public key |
| `GET /health` *public* | Liveness check |

Socket.IO: connect, then emit `authenticate {token}` (trusted device) or
`watch {challengeId, pollSecret}` (login screen). Events: `approval_request`,
`approval_resolved`, `approval_closed`.

## Limits

- Not phishing-resistant like WebAuthn: a live relay site can pass the number to the
  victim. Showing the site and location helps an attentive user; passkeys are the next step.
- IP geolocation is approximate, and VPNs distort it. Location is a risk signal, not proof.
- If a user loses every trusted device they cannot approve a new one, so account
  recovery needs a separate path.
- Behind a proxy, set `TRUST_PROXY` or every IP-based score is wrong.
- Risk weights are hand-set and not tuned on data.

Background reading is in [docs/literature-survey.md](docs/literature-survey.md).
