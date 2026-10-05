import geoip from 'geoip-lite';

const EARTH_RADIUS_KM = 6371;
const toRad = (deg) => (deg * Math.PI) / 180;

// Great-circle distance between two [lat, lon] points, in km.
const haversineKm = ([lat1, lon1], [lat2, lon2]) => {
  const dLat = toRad(lat2 - lat1);
  const dLon = toRad(lon2 - lon1);
  const a =
    Math.sin(dLat / 2) ** 2 +
    Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.sin(dLon / 2) ** 2;
  return 2 * EARTH_RADIUS_KM * Math.asin(Math.sqrt(a));
};

const normalizeIp = (ip) => (ip || '').replace(/^::ffff:/, '');

// Returns null for private, loopback or unknown addresses.
const lookupGeo = (ip) => {
  const hit = geoip.lookup(normalizeIp(ip));
  if (!hit || !hit.ll) return null;
  return {
    country: hit.country,
    region: hit.region,
    city: hit.city,
    lat: hit.ll[0],
    lon: hit.ll[1],
    timezone: hit.timezone,
  };
};

// Hour of day (0-23) at the given instant in an IANA time zone, or null.
const localHour = (date, timeZone) => {
  if (!timeZone) return null;
  try {
    const hour = new Intl.DateTimeFormat('en-GB', {
      hour: 'numeric',
      hourCycle: 'h23',
      timeZone,
    }).format(date);
    return Number(hour);
  } catch {
    return null;
  }
};

export { haversineKm, normalizeIp, lookupGeo, localHour };
