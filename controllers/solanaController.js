// backend/src/controllers/solanaController.js

import { PublicKey } from '@solana/web3.js';

// Function to verify the signature sent from the frontend
export const verifySolanaMessage = async (req, res) => {
  const { message, signature, publicKey } = req.body;

  try {
    const decodedMessage = new TextDecoder().decode(new Uint8Array(signature));

    // Check if the signed message matches the original message
    const isVerified = await verifySignature(message, signature, publicKey);

    if (isVerified) {
      res.status(200).json({ message: 'Signature verified, authentication successful' });
    } else {
      res.status(400).json({ message: 'Signature verification failed' });
    }
  } catch (err) {
    res.status(500).json({ message: 'Error verifying signature' });
  }
};

// Helper function to verify the signature
const verifySignature = async (message, signature, publicKey) => {
  const decodedSignature = new Uint8Array(signature);
  const decodedPublicKey = new PublicKey(publicKey);

  try {
    const verified = await decodedPublicKey.verify(message, decodedSignature);
    return verified;
  } catch (err) {
    return false;
  }
};
