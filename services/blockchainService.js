import { connection } from '../config/blockchain.js';
import { PublicKey } from '@solana/web3.js';

// Check Solana wallet balance
const getSolanaBalance = async (publicKey) => {
  try {
    const balance = await connection.getBalance(new PublicKey(publicKey));
    return balance / 1000000000; // Convert from lamports to SOL
  } catch (error) {
    throw new Error('Error fetching Solana balance');
  }
};

// Store encrypted backup on Solana blockchain
const storeBackupOnBlockchain = async (encryptedData, publicKey, privateKey) => {
  // Implement blockchain backup logic here (for example, sending encrypted data via a transaction)
  // This can involve creating a transaction and sending it to the blockchain network
};

export { getSolanaBalance, storeBackupOnBlockchain };
