import crypto from 'crypto';

// Encrypt data using AES-256-CBC (place-holder for future quantum-resistant encryption)
const encryptData = (data, secretKey) => {
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(secretKey), Buffer.from(secretKey).slice(0, 16));
  let encrypted = cipher.update(data, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return encrypted;
};

// Decrypt data using AES-256-CBC (place-holder for future quantum-resistant encryption)
const decryptData = (encryptedData, secretKey) => {
  const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(secretKey), Buffer.from(secretKey).slice(0, 16));
  let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
};

export { encryptData, decryptData };
