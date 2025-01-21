import { Connection, Keypair } from '@solana/web3.js';
import { solanaConfig } from './env.js';

const connection = new Connection(solanaConfig.rpcUrl, 'confirmed');

const createSolanaWallet = () => {
  const keypair = Keypair.generate();
  const publicKey = keypair.publicKey.toBase58();
  const privateKey = Buffer.from(keypair.secretKey).toString('base64');

  return { publicKey, privateKey };
};

export { connection, createSolanaWallet };
