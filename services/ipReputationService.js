import fs from 'fs';
import net from 'net';
import { config } from '../config/env.js';

let ranges;

// CIDR ranges of VPNs, proxies and datacentres, one per line (# comments allowed).
// Public lists such as X4BNet/lists_vpn work; supply the file via IP_RANGES_FILE.
const load = () => {
  ranges = new net.BlockList();
  if (!config.ipRangesFile) return;
  for (const line of fs.readFileSync(config.ipRangesFile, 'utf8').split('\n')) {
    const entry = line.split('#')[0].trim();
    const [address, prefix] = entry.split('/');
    const family = net.isIP(address);
    if (!family) continue;
    ranges.addSubnet(address, Number(prefix ?? (family === 4 ? 32 : 128)), family === 4 ? 'ipv4' : 'ipv6');
  }
};

const isAnonymizingIp = (ip) => {
  if (!ranges) load();
  const family = net.isIP(ip);
  return family !== 0 && ranges.check(ip, family === 4 ? 'ipv4' : 'ipv6');
};

export { isAnonymizingIp };
