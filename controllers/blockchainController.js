import { createSolanaWallet, connection } from '../config/blockchain.js';
import { PublicKey } from '@solana/web3.js';

// Create new Solana wallet
const createWallet = (req, res) => {
  try {
    const { publicKey, privateKey } = createSolanaWallet();
    res.status(200).json({ publicKey, privateKey });
  } catch (error) {
    res.status(500).json({ message: 'Error creating wallet' });
  }
};

// Check Solana wallet balance
const checkBalance = async (req, res) => {
  const { publicKey } = req.body;

  try {
    const balance = await connection.getBalance(new PublicKey(publicKey));
    res.status(200).json({ balance: balance / 1000000000 }); // Convert to SOL (1 SOL = 10^9 lamports)
  } catch (error) {
    res.status(500).json({ message: 'Error fetching balance' });
  }
};

export { createWallet, checkBalance };
