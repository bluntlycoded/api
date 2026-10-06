# FraudShield Authenticator API

Backend for an authenticator app: stores TOTP secrets per user, generates codes, and
protects sign-in with device trust, per-login risk scoring, impossible-travel checks
and number-matched approval.

Node 20+, Express, Postgres on Supabase, Socket.IO.

## Setup

```bash
npm install
cp .env.example .env     # fill in DATABASE_URL, JWT_SECRET, ENCRYPTION_KEY
npm run migrate          # creates the tables (supabase/migrations/*.sql)
npm run dev              # or: npm start
npm test
```

Generate secrets with `openssl rand -hex 32`. Keep `ENCRYPTION_KEY` safe: authenticator
secrets are encrypted with it (AES-256-GCM) and cannot be recovered without it.

The server connects straight to Postgres, not through Supabase's REST API.
`0002_lockdown.sql` turns on row level security with no policies and revokes the
`anon` and `authenticated` roles, so the public Supabase keys can't read any table.
On a plain Postgres without those roles, delete that file before running the migration.

## Try the web client

```bash
npm run dev:memory       # whole app on an in-memory database, no Supabase or .env needed
```

Open http://localhost:2700/app/ and register. To play a second device, open another tab with
`?profile=laptop` (any name): each profile keeps its own device identity and session. Log in as
the same user there, and the first tab receives the approval prompt live. Everything is lost
when the server stops. Against a real database the same client is served at `/app/`.

The client is plain HTML and ES modules in `public/` with no build step. It builds the page
with text nodes only, because the approval screen shows text an attacker controls (the site
and device name); a test fails if `innerHTML` or similar appears. It keeps the refresh token in
`localStorage`, which is fine for a demo but means any script injected into the page could read
it; a production web app should use an httpOnly cookie instead.

Tests run against an in-memory Postgres (pg-mem) with the real schema, so they need no database.

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
   | New country | 30 |
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
| `POST /api/auth/refresh` *public* | Trade a refresh token for a new access token and refresh token (each works once) |
| `POST /api/auth/logout` *public*, `POST /api/auth/logout-all` | End this login, or every login on every device |
| `POST /api/auth/recover` *public* | Lost every device: password plus a recovery code starts a session on this device |
| `GET /api/recovery`, `POST /api/recovery` *trusted* | Count of unused recovery codes; generate ten new ones (needs the password) |
| `POST /api/auth/forgot-password` *public* | Email a reset link (same reply for unknown emails) |
| `POST /api/auth/reset-password` *public* | Set a new password with the emailed token |
| `POST /api/auth/passkey/options`, `POST /api/auth/passkey/verify` *public* | Sign in with a passkey (no password, no approval step) |
| `POST /api/addapp` | Save an entry: `appName`, base32 `secretKey`, optional `issuer`, `account`, `type` (totp/hotp), `algorithm`, `digits`, `period`, `counter`, `folder`, `icon`, `favorite` |
| `GET /api/addapp?q=&folder=&favorite=` | List or search entries |
| `PATCH /api/addapp/:appId` | Rename, move to a folder, set icon or favorite |
| `PUT /api/addapp/order` | `{ids: [...]}` sets the display order |
| `GET /api/addapp/:appId/otp` | Current code (HOTP advances its counter) |
| `DELETE /api/addapp/:appId` | Delete an entry |
| `POST /api/addapp/import` | `{data}`: `otpauth://` URIs, a Google Authenticator export link, or an unencrypted Aegis export |
| `POST /api/addapp/export` *trusted* | `{password}` returns `otpauth://` URIs |
| `GET/PUT/DELETE /api/vault` | End-to-end encrypted backup blob (see below). Writes need a *trusted* device |
| `GET /api/passkeys`, `POST /api/passkeys/options`, `POST /api/passkeys/verify`, `DELETE /api/passkeys/:id` *trusted* | Manage passkeys |
| `POST /api/approval/:id/report` *trusted* | "This wasn't me": denies, blocks the IP for 7 days, locks the account until a password reset |
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

## Sessions and recovery

Access tokens last 15 minutes. Every login also returns a refresh token (30 days, and at most
90 days from the original login). Refresh tokens rotate: using one returns a new one and
retires the old. Presenting an already-used token means it was copied, so that whole login
is ended and the event is audited. Removing a device, resetting the password, "this wasn't
me", logout-all and account recovery all end the affected refresh tokens; an access token
already issued still works until it expires (up to 15 minutes).

Recovery codes are ten single-use codes (60 bits each) stored only as hashes and shown once.
Recovering from a new device needs the password and one code, makes that device the only
trusted one, ends every other session and emails a notice. A locked account cannot recover;
it needs a password reset.

## Encrypted backup

`/api/vault` stores one opaque blob per user. The app encrypts it on the device (for
example with a key derived from a passphrase) and the server never sees the key or the
contents. `PUT` sends `{ciphertext, version}` where `version` is the one last read
(`0` for the first upload); a stale version gets `409` so devices can't overwrite each
other. The app can use this for sync and restore without trusting the server.

## Tuning the risk weights

```bash
npm run evaluate:risk -- --synthetic             # pipeline check only
npm run evaluate:risk -- path/to/rba-dataset.csv # public login dataset (Wiefling et al.)
```

It replays logins through the real scorer and prints, for each challenge threshold, the
share of legitimate logins challenged and attacker logins challenged, plus how often
each signal fires. Adjust `config/risk.js` from that. VPN/proxy detection reads CIDR
ranges from `IP_RANGES_FILE`.

## Limits

- Not phishing-resistant like WebAuthn: a live relay site can pass the number to the
  victim. Showing the site and location helps an attentive user; passkeys are the next step.
- IP geolocation is approximate, and VPNs distort it. Location is a risk signal, not proof.
- If a user loses every trusted device they cannot approve a new one, so account
  recovery needs a separate path.
- Passkey login is verified against the WebAuthn library only; it has not been exercised
  with a real authenticator yet. Passkey login skips the approval step by design.
- Push notifications and device attestation (Play Integrity / App Attest) are not built;
  both need Google or Apple credentials.
- Behind a proxy, set `TRUST_PROXY` or every IP-based score is wrong.
- Risk weights are hand-set and not tuned on data.

Background reading is in [docs/literature-survey.md](docs/literature-survey.md).
