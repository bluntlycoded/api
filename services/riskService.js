import {
  RISK_WEIGHTS,
  APPROVAL_THRESHOLD,
  MAX_TRAVEL_SPEED_KMH,
  MIN_TRAVEL_DISTANCE_KM,
  MIN_TRAVEL_GAP_SECONDS,
  ODD_HOURS,
  FAILURE_LIMIT,
} from '../config/risk.js';
import { haversineKm } from '../utils/geo.js';

const hasCoords = (geo) => geo && typeof geo.lat === 'number' && typeof geo.lon === 'number';

// Implied speed (km/h) and distance between a past login and the current one.
const travelBetween = (previous, current, now) => {
  const distanceKm = haversineKm([previous.geo.lat, previous.geo.lon], [current.lat, current.lon]);
  const gapSeconds = Math.max((now - new Date(previous.at)) / 1000, MIN_TRAVEL_GAP_SECONDS);
  return { distanceKm, speedKmh: distanceKm / (gapSeconds / 3600) };
};

/**
 * Score one login attempt. Pure function: no I/O.
 *
 * @param {object}  p
 * @param {Date}    p.now
 * @param {boolean} p.deviceTrusted     device is known and trusted for this user
 * @param {string}  p.ip
 * @param {object|null} p.geo           {country, lat, lon, ...} or null if unknown
 * @param {number|null} p.localHour     current hour in the IP's time zone, or null
 * @param {boolean} p.originUnrecognized request Origin is set and not allow-listed
 * @param {number}  p.recentFailures    failed password attempts in the recent window
 * @param {Array}   p.history           past successful logins, newest first:
 *                                      {ip, geo, localHour, at}
 * @returns {{score:number, requiresApproval:boolean, signals:Array}}
 */
const scoreLogin = ({
  now,
  deviceTrusted,
  ip,
  geo,
  localHour,
  originUnrecognized = false,
  recentFailures = 0,
  history,
}) => {
  const signals = [];
  const add = (id, detail) => signals.push({ id, points: RISK_WEIGHTS[id], detail });

  // First ever login: nothing to compare against, so it becomes the baseline.
  if (history.length === 0 && !deviceTrusted) {
    return { score: 0, requiresApproval: false, signals, baseline: true };
  }

  if (!deviceTrusted) add('newDevice', 'Sign-in from a device that is not trusted');
  if (originUnrecognized) add('unrecognizedOrigin', 'Request came from an unrecognized website');

  if (!history.some((h) => h.ip === ip)) add('newIp', 'IP address not seen in recent logins');

  if (geo) {
    const seenCountries = history.filter((h) => h.geo).map((h) => h.geo.country);
    if (seenCountries.length > 0 && !seenCountries.includes(geo.country)) {
      add('newCountry', `First login from ${geo.country}`);
    }

    // Compare with the most recent login that has coordinates and a different IP.
    const previous = history.find((h) => hasCoords(h.geo) && h.ip !== ip);
    if (previous && hasCoords(geo)) {
      const { distanceKm, speedKmh } = travelBetween(previous, geo, now);
      if (distanceKm >= MIN_TRAVEL_DISTANCE_KM && speedKmh > MAX_TRAVEL_SPEED_KMH) {
        add(
          'impossibleTravel',
          `${Math.round(distanceKm)} km from the last login in ${Math.round(
            (now - new Date(previous.at)) / 60000
          )} min (~${Math.round(speedKmh)} km/h)`
        );
      }
    }
  }

  if (localHour !== null && localHour >= ODD_HOURS.start && localHour < ODD_HOURS.end) {
    const usualAtThisHour = history.some((h) => h.localHour === localHour);
    if (!usualAtThisHour) add('oddHour', `Login at ${localHour}:00 local time, which is unusual for this account`);
  }

  if (recentFailures >= FAILURE_LIMIT) add('recentFailures', `${recentFailures} failed passwords just before this login`);

  const score = Math.min(100, signals.reduce((sum, s) => sum + s.points, 0));
  return { score, requiresApproval: score >= APPROVAL_THRESHOLD, signals };
};

export { scoreLogin };
