import { body, param, validationResult } from 'express-validator';
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

const mongoId = (field) => param(field, `Invalid ${field}`).isMongoId();

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
  body('challengeId', 'Invalid challengeId').isMongoId(),
  hexToken(body, 'pollSecret'),
  deviceId
);

export const forgotPasswordRules = validate(email);

export const resetPasswordRules = validate(hexToken(body, 'token'), newPassword());

export const addAppRules = validate(
  body('appName', 'App name is required').isString().trim().isLength({ min: 1, max: 100 }),
  body('secretKey', 'Secret key must be a base32 string of at least 16 characters')
    .isString()
    .customSanitizer((value) => value.replace(/[\s-]/g, '').toUpperCase())
    .matches(/^[A-Z2-7]{16,128}=*$/)
);

export const appIdRules = validate(mongoId('appId'));

export const deviceIdRules = validate(mongoId('id'));

export const approvalRespondRules = validate(
  mongoId('id'),
  body('action', 'action must be approve or deny').isIn(['approve', 'deny']),
  body('choice', 'choice must be a two-digit number').optional().isInt({ min: 10, max: 99 }).toInt(),
  body('trustDevice').optional().isBoolean().toBoolean()
);

export const approvalStatusRules = validate(mongoId('id'), hexToken(body, 'pollSecret'));

export const totpCodeRules = validate(otpCode('token'));

export const totpDisableRules = validate(
  otpCode('token'),
  body('password', 'Password is required').isString().notEmpty()
);

export const balanceRules = validate(body('publicKey', 'Invalid public key').isString().isLength({ min: 32, max: 44 }));
