import { PublicKey } from '@solana/web3.js';
import { connection, createSolanaWallet } from '../config/blockchain.js';
import { HttpError } from '../utils/httpError.js';
import { asyncHandler } from '../utils/asyncHandler.js';

const LAMPORTS_PER_SOL = 1e9;

// The private key is returned once and never stored.
const createWallet = (req, res) => res.status(200).json(createSolanaWallet());

const checkBalance = asyncHandler(async (req, res) => {
  let publicKey;
  try {
    publicKey = new PublicKey(req.body.publicKey);
  } catch {
    throw new HttpError(400, 'Invalid public key');
  }
  const lamports = await connection.getBalance(publicKey);
  res.status(200).json({ balance: lamports / LAMPORTS_PER_SOL });
});

export { createWallet, checkBalance };
