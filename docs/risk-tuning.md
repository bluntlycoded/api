# Risk weight tuning

Run on 2026-10-06 with `npm run evaluate:risk` against the public Login Data Set for
Risk-Based Authentication (Wiefling, Jørgensen, Thunem, Lo Iacono; Zenodo
10.5281/zenodo.6782155, CC BY 4.0, md5 cc1b1078b3929650e6c08678caffcc57).

## Setup

- 31.3M rows read. Kept a 1-in-20 sample of users plus all 138 users with an account
  takeover: 587,874 legitimate logins and 140 takeovers. Half the users trained the
  weights, the other half only measured them.
- Legitimate: successful login, not from an attack IP, not a takeover. Attacker: account
  takeover (the attacker had the password, which is what risk scoring is for).
- Location is the dataset's Country column and local hour is Europe/Oslo. The dataset's
  IPs are synthetic, so they are not looked up.
- Challenge threshold stays 40. The budget was at most 2% of legitimate logins challenged.

## What the data can and cannot tell us

| Signal | Fires on legit / takeover | Tuned? |
|---|---|---|
| newCountry | 0.56% / 47.9% | Yes. By far the strongest signal. |
| oddHour | 2.0% / 9.3% | Yes, no change |
| newIp | 30.6% / 56.4% | Yes, no change. Weak: most legitimate users change IP. |
| newDevice | 15.5% / 27.9% | No. The data has no device id; the user-agent stand-in is noisy and a real app's device id is stable. Kept at 40. |
| impossibleTravel | never | No. No coordinates in the data. Kept at 60. |

Failed passwords, unrecognized origin and VPN/proxy IPs are not in the data either.

## Result

With the new-device signal switched off to remove its noise, the old weights challenged
8.2% of held-out takeovers (0.02% of legitimate logins). Raising newCountry from 25 to 30
makes a new country plus a new IP reach the threshold, and challenges 52.1% of held-out
takeovers for 0.53% of legitimate logins (train: 43.3% for 0.58%). newIp (10) and
oddHour (15) stayed. In production a new device adds its own 40 points, so more
takeovers are caught than these figures show.

## Caveats

- Synthetic data. Its authors warn against using it in production systems.
- Only 140 takeovers, 73 in the held-out half, so the held-out rate carries a few
  percentage points of error. Treat 30 as a data-informed starting point, not an optimum.
- With the original newDevice weight on, the search could not meet the 2% budget
  because the noisy device signal alone challenges 15% of legitimate logins; it changed
  nothing useful, so that run's output was not applied.
- Re-run on real login data from this app once there is some.
