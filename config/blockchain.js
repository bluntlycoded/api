import { Connection, Keypair } from '@solana/web3.js';
import { config } from './env.js';

const connection = new Connection(config.solanaRpcUrl, 'confirmed');

const createSolanaWallet = () => {
  const keypair = Keypair.generate();
  return {
    publicKey: keypair.publicKey.toBase58(),
    privateKey: Buffer.from(keypair.secretKey).toString('base64'),
  };
};

export { connection, createSolanaWallet };
