import * as vaults from '../repositories/vaultRepository.js';
import { audit } from '../services/auditService.js';
import { HttpError } from '../utils/httpError.js';
import { asyncHandler } from '../utils/asyncHandler.js';

// The ciphertext is produced and opened on the device; the server cannot read it.
const getVault = asyncHandler(async (req, res) => {
  const vault = await vaults.get(req.user.userId);
  if (!vault) throw new HttpError(404, 'No backup stored');
  res.status(200).json(vault);
});

// `version` is the version the client last saw (0 for a first upload).
// A stale version is rejected so one device cannot silently overwrite another's changes.
const putVault = asyncHandler(async (req, res) => {
  const version = await vaults.put(req.user.userId, req.body.ciphertext, req.body.version);
  if (version === null) {
    const current = await vaults.get(req.user.userId);
    throw new HttpError(409, 'Backup changed on another device', { currentVersion: current?.version ?? 0 });
  }
  await audit(req.user.userId, 'vault_updated', req.ip, { version });
  res.status(200).json({ version });
});

const deleteVault = asyncHandler(async (req, res) => {
  if (!(await vaults.remove(req.user.userId))) throw new HttpError(404, 'No backup stored');
  await audit(req.user.userId, 'vault_deleted', req.ip);
  res.status(200).json({ message: 'Backup deleted' });
});

export { getVault, putVault, deleteVault };
