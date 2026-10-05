// Tunable parameters for risk-based login scoring.
// Weights are additive and the total is capped at 100.

export const RISK_WEIGHTS = {
  newDevice: 40,
  unrecognizedOrigin: 40,
  impossibleTravel: 60,
  newCountry: 25,
  recentFailures: 20,
  anonymizingIp: 15,
  oddHour: 15,
  newIp: 10,
};

// Score at or above this forces the approve prompt on a trusted device.
export const APPROVAL_THRESHOLD = 40;

// Travel faster than this (km/h) between two successful logins is "impossible".
export const MAX_TRAVEL_SPEED_KMH = 900;
// IP geolocation is city-level at best, so ignore short hops.
export const MIN_TRAVEL_DISTANCE_KM = 100;
// Treat a gap shorter than this as this long, to avoid divide-by-near-zero.
export const MIN_TRAVEL_GAP_SECONDS = 60;

// Local-time window (hours, inclusive start, exclusive end) treated as unusual
// unless the user has logged in during that hour before.
export const ODD_HOURS = { start: 0, end: 5 };

export const HISTORY_SIZE = 50;
export const FAILURE_WINDOW_MINUTES = 15;
export const FAILURE_LIMIT = 3;

// Approval challenge (number matching).
export const APPROVAL_TTL_SECONDS = 120;
export const APPROVAL_MAX_WRONG_ATTEMPTS = 2;
export const APPROVAL_MAX_PENDING = 3;
export const APPROVAL_MAX_PER_HOUR = 5;

// How long an IP reported as "not me" stays blocked.
export const BLOCK_DAYS = 7;

// Failed credentials within the failure window before logins are refused outright.
export const LOCKOUT_FAILURES = 10;
