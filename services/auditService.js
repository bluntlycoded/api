import { recordAudit } from '../repositories/eventRepository.js';

// Security-relevant account events. Failures are logged, never thrown, so an
// audit write can't break the request that triggered it.
const audit = (userId, type, ip, details) =>
  recordAudit(userId, type, ip, details).catch((err) => console.error('Audit write failed:', err.message));

export { audit };
