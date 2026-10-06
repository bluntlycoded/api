import { body, param, query, validationResult } from 'express-validator';
import { HttpError } from '../utils/httpError.js';

// Runs the rules, then rejects with the first error message.
const validate = (...rules) => [
  ...rules,
  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) throw new HttpError(400, errors.array()[0].msg);
    next();
  },
];

const email = body('email', 'A valid email is required').isString().trim().toLowerCase().isEmail();

// bcrypt ignores everything past 72 bytes.
const newPassword = (field = 'password') =>
  body(field, 'Password must be 8-72 characters with at least one letter and one number')
    .isString()
    .isLength({ min: 8, max: 72 })
    .matches(/^(?=.*[A-Za-z])(?=.*\d)/);

const deviceId = body('deviceId', 'A valid deviceId is required').isString().isLength({ min: 16, max: 200 });

const deviceName = body('deviceName').optional().isString().trim().isLength({ max: 80 });

const otpCode = (field) =>
  body(field, `${field} must be a 6-digit code`).isString().matches(/^\d{6}$/);

const hexToken = (source, field) =>
  source(field, `Invalid ${field}`).isString().isHexadecimal().isLength({ min: 64, max: 64 });

const uuidParam = (field) => param(field, `Invalid ${field}`).isUUID();

export const registerRules = validate(
  body('name', 'Name is required').isString().trim().isLength({ min: 1, max: 100 }),
  email,
  newPassword(),
  deviceId,
  deviceName
);

export const loginRules = validate(
  email,
  body('password', 'Password is required').isString().notEmpty(),
  deviceId,
  deviceName,
  body('totp', 'totp must be a 6-digit code').optional().isString().matches(/^\d{6}$/)
);

export const completeLoginRules = validate(
  body('challengeId', 'Invalid challengeId').isUUID(),
  hexToken(body, 'pollSecret'),
  deviceId
);

export const forgotPasswordRules = validate(email);

export const resetPasswordRules = validate(hexToken(body, 'token'), newPassword());

const optionalText = (field, max) => body(field, `${field} is too long`).optional({ nullable: true }).isString().trim().isLength({ max });

const appFields = [
  optionalText('issuer', 100),
  optionalText('account', 100),
  optionalText('folder', 50),
  optionalText('icon', 100),
  body('favorite', 'favorite must be true or false').optional().isBoolean().toBoolean(),
];

export const addAppRules = validate(
  body('appName', 'App name is required').isString().trim().isLength({ min: 1, max: 100 }),
  body('secretKey', 'Secret key must be a base32 string of at least 16 characters')
    .isString()
    .customSanitizer((value) => value.replace(/[\s-]/g, '').toUpperCase())
    .matches(/^[A-Z2-7]{16,128}=*$/),
  body('type', 'type must be totp or hotp').optional().isIn(['totp', 'hotp']),
  body('algorithm', 'algorithm must be SHA1, SHA256 or SHA512').optional().isIn(['SHA1', 'SHA256', 'SHA512']),
  body('digits', 'digits must be 6, 7 or 8').optional().isIn([6, 7, 8]),
  body('period', 'period must be 15-120 seconds').optional().isInt({ min: 15, max: 120 }).toInt(),
  body('counter', 'counter must be 0 or more').optional().isInt({ min: 0 }).toInt(),
  ...appFields
);

export const updateAppRules = validate(
  uuidParam('appId'),
  body('appName', 'App name cannot be empty').optional().isString().trim().isLength({ min: 1, max: 100 }),
  ...appFields
);

export const listAppRules = validate(
  query('q').optional().isString().isLength({ max: 100 }),
  query('folder').optional().isString().isLength({ max: 50 }),
  query('favorite').optional().isBoolean().toBoolean()
);

export const reorderRules = validate(
  body('ids', 'ids must be a list of 1-500 entry ids').isArray({ min: 1, max: 500 }),
  body('ids.*', 'Invalid id').isUUID()
);

export const countersRules = validate(
  body('counters', 'counters must be a list of 1-100 entries').isArray({ min: 1, max: 100 }),
  body('counters.*.id', 'Invalid id').isUUID(),
  body('counters.*.counter', 'counter must be 0 or more').isInt({ min: 0 }).toInt()
);

export const importRules = validate(
  body('data', 'data is required').custom((v) => typeof v === 'string' || (typeof v === 'object' && v !== null))
);

export const exportRules = validate(body('password', 'Password is required').isString().notEmpty());

export const appIdRules = validate(uuidParam('appId'));

export const deviceIdRules = validate(uuidParam('id'));

export const approvalRespondRules = validate(
  uuidParam('id'),
  body('action', 'action must be approve or deny').isIn(['approve', 'deny']),
  body('choice', 'choice must be a two-digit number').optional().isInt({ min: 10, max: 99 }).toInt(),
  body('trustDevice').optional().isBoolean().toBoolean()
);

export const approvalStatusRules = validate(uuidParam('id'), hexToken(body, 'pollSecret'));

export const totpCodeRules = validate(otpCode('token'));

export const totpDisableRules = validate(
  otpCode('token'),
  body('password', 'Password is required').isString().notEmpty()
);

export const balanceRules = validate(body('publicKey', 'Invalid public key').isString().isLength({ min: 32, max: 44 }));

export const vaultRules = validate(
  body('ciphertext', 'ciphertext must be a base64url string').isString().matches(/^[A-Za-z0-9_-]+$/).isLength({ max: 1_000_000 }),
  body('version', 'version must be 0 or more').isInt({ min: 0 }).toInt()
);

export const passkeyVerifyRules = validate(
  body('challengeId', 'Invalid challengeId').isUUID(),
  body('response', 'response is required').isObject(),
  optionalText('name', 80)
);

export const passkeyLoginRules = validate(
  body('challengeId', 'Invalid challengeId').isUUID(),
  body('response', 'response is required').isObject(),
  deviceId,
  deviceName
);

export const reportRules = validate(uuidParam('id'));

export const refreshRules = validate(hexToken(body, 'refreshToken'));

export const recoverRules = validate(
  email,
  body('password', 'Password is required').isString().notEmpty(),
  body('recoveryCode', 'Recovery code is required').isString().isLength({ min: 12, max: 20 }),
  deviceId,
  deviceName
);
