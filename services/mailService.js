import nodemailer from 'nodemailer';
import { config } from '../config/env.js';

let transport;

const getTransport = () => {
  if (!config.smtp.host) return null;
  transport ??= nodemailer.createTransport({
    host: config.smtp.host,
    port: config.smtp.port,
    secure: config.smtp.port === 465,
    auth: config.smtp.user ? { user: config.smtp.user, pass: config.smtp.pass } : undefined,
  });
  return transport;
};

const sendPasswordReset = async (email, token) => {
  const link = config.passwordResetUrl ? `${config.passwordResetUrl}?token=${token}` : null;
  const smtp = getTransport();

  if (!smtp) {
    if (config.env === 'production') throw new Error('SMTP is not configured');
    console.log(`[dev] password reset for ${email}: ${link || token}`);
    return;
  }

  await smtp.sendMail({
    from: config.smtp.from,
    to: email,
    subject: 'Reset your password',
    text: [
      'We received a request to reset your password.',
      link ? `Open this link within 15 minutes: ${link}` : `Your reset code (valid 15 minutes): ${token}`,
      'If you did not ask for this, you can ignore this email.',
    ].join('\n\n'),
  });
};

// Best-effort heads-up about a sensitive account event.
const sendSecurityNotice = async (email, subject, text) => {
  const smtp = getTransport();
  if (!smtp) {
    if (config.env !== 'production') console.log(`[dev] notice to ${email}: ${subject}`);
    return;
  }
  await smtp.sendMail({ from: config.smtp.from, to: email, subject, text });
};

export { sendPasswordReset, sendSecurityNotice };
