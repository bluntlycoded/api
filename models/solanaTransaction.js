import mongoose from 'mongoose';

const solanaTransactionSchema = new mongoose.Schema({
  senderPublicKey: {
    type: String,
    required: true,
  },
  receiverPublicKey: {
    type: String,
    required: true,
  },
  amount: {
    type: Number,
    required: true,
  },
  transactionHash: {
    type: String,
    required: true,
  },
  timestamp: {
    type: Date,
    default: Date.now,
  },
});

const SolanaTransaction = mongoose.model('SolanaTransaction', solanaTransactionSchema);

export default SolanaTransaction;
