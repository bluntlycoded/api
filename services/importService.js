import { HttpError } from '../utils/httpError.js';

const MAX_ENTRIES = 500;
const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const ALGORITHMS = ['SHA1', 'SHA256', 'SHA512'];

const base32Encode = (bytes) => {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += BASE32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += BASE32[(value << (5 - bits)) & 31];
  return out;
};

const cleanSecret = (secret) => String(secret || '').replace(/[\s-]/g, '').replace(/=+$/, '').toUpperCase();

// Fills defaults and drops values the schema would reject. Returns null if unusable.
const normalize = (entry) => {
  const secretKey = cleanSecret(entry.secretKey);
  if (!/^[A-Z2-7]{16,128}$/.test(secretKey) || !entry.appName) return null;
  const type = entry.type === 'hotp' ? 'hotp' : 'totp';
  const algorithm = ALGORITHMS.includes(entry.algorithm) ? entry.algorithm : 'SHA1';
  const digits = [6, 7, 8].includes(entry.digits) ? entry.digits : 6;
  const period = Number.isInteger(entry.period) && entry.period >= 15 && entry.period <= 120 ? entry.period : 30;
  return {
    appName: String(entry.appName).slice(0, 100),
    issuer: entry.issuer ? String(entry.issuer).slice(0, 100) : undefined,
    account: entry.account ? String(entry.account).slice(0, 100) : undefined,
    secretKey,
    type,
    algorithm,
    digits,
    period,
    counter: type === 'hotp' && Number.isInteger(entry.counter) && entry.counter >= 0 ? entry.counter : 0,
    icon: entry.icon ? String(entry.icon).slice(0, 100) : undefined,
  };
};

// otpauth://totp/Issuer:account?secret=...&issuer=...&algorithm=SHA1&digits=6&period=30
const parseOtpauthUri = (uri) => {
  let url;
  try {
    url = new URL(uri);
  } catch {
    return null;
  }
  if (url.protocol !== 'otpauth:' || !['totp', 'hotp'].includes(url.host)) return null;

  const label = decodeURIComponent(url.pathname.replace(/^\//, ''));
  const [labelIssuer, ...rest] = label.includes(':') ? label.split(':') : [undefined, label];
  const issuer = url.searchParams.get('issuer') || labelIssuer?.trim();
  const account = rest.join(':').trim();
  const num = (name) => (url.searchParams.has(name) ? Number(url.searchParams.get(name)) : undefined);

  return normalize({
    appName: issuer || account,
    issuer,
    account,
    secretKey: url.searchParams.get('secret'),
    type: url.host,
    algorithm: (url.searchParams.get('algorithm') || 'SHA1').toUpperCase(),
    digits: num('digits'),
    period: num('period'),
    counter: num('counter'),
  });
};

// Minimal protobuf reader for Google Authenticator's export format.
const readVarint = (buf, pos) => {
  let result = 0;
  let shift = 0;
  for (;;) {
    const byte = buf[pos.i++];
    result += (byte & 0x7f) * 2 ** shift;
    if (!(byte & 0x80)) return result;
    shift += 7;
  }
};

const readFields = (buf) => {
  const pos = { i: 0 };
  const fields = [];
  while (pos.i < buf.length) {
    const tag = readVarint(buf, pos);
    const field = tag >>> 3;
    const wire = tag & 7;
    if (wire === 0) fields.push({ field, value: readVarint(buf, pos) });
    else if (wire === 2) {
      const len = readVarint(buf, pos);
      fields.push({ field, value: buf.subarray(pos.i, pos.i + len) });
      pos.i += len;
    } else throw new Error('Unsupported protobuf wire type');
  }
  return fields;
};

const GOOGLE_ALGORITHMS = { 1: 'SHA1', 2: 'SHA256', 3: 'SHA512' };

// otpauth-migration://offline?data=<base64 of MigrationPayload>
const parseGoogleMigration = (uri) => {
  const data = new URL(uri).searchParams.get('data');
  if (!data) return [];
  const payload = readFields(Buffer.from(data.replace(/ /g, '+'), 'base64'));
  return payload
    .filter((f) => f.field === 1)
    .map((f) => {
      const p = Object.fromEntries(readFields(f.value).map((x) => [x.field, x.value]));
      const name = p[2]?.toString('utf8') || '';
      const issuer = p[3]?.toString('utf8') || undefined;
      return normalize({
        appName: issuer || name,
        issuer,
        account: name,
        secretKey: p[1] ? base32Encode(p[1]) : '',
        algorithm: GOOGLE_ALGORITHMS[p[4]],
        digits: p[5] === 2 ? 8 : 6,
        type: p[6] === 1 ? 'hotp' : 'totp',
        counter: p[7],
      });
    });
};

// Unencrypted Aegis export: {db: {entries: [{type, name, issuer, info: {...}}]}}
const parseAegis = (json) => {
  if (json?.header?.slots && typeof json.db === 'string') {
    throw new HttpError(400, 'This Aegis export is encrypted. Export it without a password and try again.');
  }
  return (json?.db?.entries || []).map((e) =>
    normalize({
      appName: e.issuer || e.name,
      issuer: e.issuer,
      account: e.name,
      secretKey: e.info?.secret,
      type: e.type,
      algorithm: String(e.info?.algo || 'SHA1').toUpperCase(),
      digits: e.info?.digits,
      period: e.info?.period,
      counter: e.info?.counter,
    })
  );
};

// Accepts otpauth:// URIs, an otpauth-migration:// URI, or an Aegis JSON export,
// either as a string (one item per line) or a parsed object.
const parseImport = (data) => {
  let entries;
  if (typeof data === 'object' && data !== null) entries = parseAegis(data);
  else {
    const text = String(data).trim();
    if (text.startsWith('{')) entries = parseAegis(JSON.parse(text));
    else
      entries = text
        .split(/\s*\n\s*/)
        .filter(Boolean)
        .flatMap((line) => (line.startsWith('otpauth-migration:') ? parseGoogleMigration(line) : [parseOtpauthUri(line)]));
  }
  if (entries.length > MAX_ENTRIES) throw new HttpError(400, `Import is limited to ${MAX_ENTRIES} entries`);
  return { valid: entries.filter(Boolean), skipped: entries.filter((e) => !e).length };
};

const toOtpauthUri = (app) => {
  const account = app.account || app.appName;
  const label = encodeURIComponent(app.issuer ? `${app.issuer}:${account}` : account);
  const params = new URLSearchParams({ secret: app.secretKey, algorithm: app.algorithm, digits: String(app.digits) });
  if (app.issuer) params.set('issuer', app.issuer);
  if (app.type === 'hotp') params.set('counter', String(app.counter));
  else params.set('period', String(app.period));
  return `otpauth://${app.type}/${label}?${params}`;
};

export { parseImport, parseOtpauthUri, parseGoogleMigration, parseAegis, toOtpauthUri, base32Encode };
