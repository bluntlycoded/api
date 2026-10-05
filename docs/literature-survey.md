# Literature survey: risk-based login approval for an authenticator app

Scope: risk-based authentication (RBA), impossible-travel detection, push approval
with number matching, and phishing-resistant authentication. Searched 2026-10-05.
Every entry below was confirmed against a publisher, DOI, arXiv or project page
in that search. Items marked (secondary) were only seen described in another source.

## 1. Risk-based authentication

| Work | Venue | Relevance |
|---|---|---|
| Freeman, Jain, Dürmuth, Biggio, Giacinto. *Who Are You? A Statistical Approach to Measuring User Authenticity.* | NDSS 2016, doi:10.14722/ndss.2016.23240 | Early public probabilistic login risk score from IP, geolocation, browser and time of day, evaluated on LinkedIn data. Basis for the feature set used here. |
| Wiefling, Lo Iacono, Dürmuth. *Is This Really You? An Empirical Study on Risk-Based Authentication Applied in the Wild.* | IFIP SEC 2019, doi:10.1007/978-3-030-22312-0_10 | Probed 8 large services (Amazon, Google, Facebook and others). IP address was the dominant risk feature; verification codes were the usual extra factor. |
| Wiefling, Jørgensen, Thunem, Lo Iacono. *Pump Up Password Security! Evaluating and Enhancing Risk-Based Authentication on a Real-World Large-Scale Online Service.* | ACM TOPS 26(1), 2023, doi:10.1145/3546069 | 3.3M users, 31.3M logins. Storing 8 login-history entries gave a stable setup blocking 99.5% of targeted attackers in their setting. Supports keeping a short history window. |
| Wiefling et al. *Login Data Set for Risk-Based Authentication.* | Zenodo 10.5281/zenodo.6782155 | Synthetic dataset (CC BY 4.0) for evaluating RBA. The authors warn it must not be used in production systems. Candidate for offline tuning of the weights in `config/risk.js`. |
| Wiefling, Lo Iacono et al. *Risk-Based Authentication for OpenStack: A Fully Functional Implementation and Guiding Example.* | arXiv:2303.12361 (2023) | Open-source RBA implementation; closest existing code to compare against. (Only the reference list was retrieved; read before citing.) |
| Wiefling et al. *More Than Just Good Passwords? A Study on Usability and Security Perceptions of Risk-based Authentication.* | ACSAC 2020, doi:10.1145/3427228.3427243 | Lab study (n=65): RBA rated more usable than the 2FA variants studied. |
| Atlam et al. *Risk-Based Access Control Model: A Systematic Literature Review.* | Future Internet 12(6):103, 2020 | Broader than authentication (access control), but lists risk factors and estimation methods. I found no systematic review of RBA alone. |

## 2. Impossible travel and IP geolocation

| Work | Relevance |
|---|---|
| *Trackly: A Unified SaaS Platform for User Behavior Analytics and Real Time Rule Based Anomaly Detection.* arXiv:2601.22800 | Rule-based impossible travel using Haversine distance and a speed threshold near 1000 km/h; notes VPN/proxy awareness and login timing improve accuracy. This repo uses 900 km/h. |
| Poese, Uhlig, Kaafar, Donnet, Gueye. *IP Geolocation Databases: Unreliable?* ACM SIGCOMM CCR 41(2):53-56, 2011, doi:10.1145/1971162.1971171 | Ground-truth study showing commercial geolocation databases are often wrong. Reason this repo ignores hops under 100 km and treats location as a risk signal, never proof. |
| US patents 10333944 and 12463978 (impossible travel using geolocation and a speed threshold) | Prior art for the technique; not peer reviewed. |
| Vendor write-ups (Abnormal, IPinfo, Torq) | Practitioner view: VPNs, roaming and shared accounts cause false positives; attackers can use residential proxies or delay logins. Not peer reviewed. |

Limits to state in any write-up: no peer-reviewed evaluation of impossible-travel
detection turned up in this search, so its accuracy claims here are untested.

## 3. Push approval, MFA fatigue and number matching

| Work | Relevance |
|---|---|
| Jubur, Shrestha, Saxena, Prakash. *Bypassing Push-based Second Factor and Passwordless Authentication with Human-Indistinguishable Notifications (HIENA).* ASIA CCS 2021, doi:10.1145/3433210.3453084 | Shows one-tap push is not bound to the login session: near-simultaneous attacker and victim prompts look the same, and the attacker can spoof the displayed city. Motivates number matching and treating displayed location as untrusted. |
| Reese, Smith, Dutson, Armknecht, Cameron, Seamons. *A Usability Study of Five Two-Factor Authentication Methods.* SOUPS 2019 | Usability baseline for 2FA methods, including push. |
| CISA. *Implementing Number Matching in MFA Applications* (fact sheet) | Government guidance recommending number matching against push bombing. Primary source for the defence. |
| Microsoft Authenticator number matching and additional context (app name, location); Duo Verified Push (3 to 6 digit code) | Production designs of the same idea. Docs and blogs; Microsoft reports enforcing number matching from May 2023 (secondary). IP-based location shown to the user can be inaccurate. |
| Mahdad, Jubur, Saxena. concurrent-attack follow-up to HIENA, MobiCom 2023 (secondary) | Seen only as a citation in search results; verify before use. |

No peer-reviewed study of number matching itself came up; the evidence is guidance
and vendor documentation plus the HIENA attack paper. Number matching does not stop
adversary-in-the-middle phishing or social engineering of the user (secondary sources).

## 4. Phishing resistance

| Work | Relevance |
|---|---|
| Lang, Czeskis, Balfanz, Schilder, Srinivas. *Security Keys: Practical Cryptographic Second Factors for the Modern Web.* Financial Cryptography 2016, doi:10.1007/978-3-662-54970-4_25 | Origin-bound second factor, two-year Google deployment; the design FIDO standardised. |
| Lyastani, Schilling, Neumayr, Backes, Bugiel. *Is FIDO2 the Kingslayer of User Authentication? A Comparative Usability Study of FIDO2 Passwordless Authentication.* IEEE S&P 2020, doi:10.1109/SP40000.2020.00047 | Users accepted security keys as a password replacement; adoption concerns identified. |
| Kondracki, Azad, Starov, Nikiforakis. *Catching Transparent Phish: Analyzing and Detecting MITM Phishing Toolkits.* ACM CCS 2021, doi:10.1145/3460120.3484765 | Evilginx, Muraena, Modlishka relay credentials and session cookies. Only 43.7% of such domains were on blocklists. Shows why number matching alone is not phishing-proof and why WebAuthn is the real fix. |

## 5. Existing projects

| Project | What it offers | Gap relative to this work |
|---|---|---|
| Aegis (Android, open source) | Offline TOTP/HOTP vault, AES-256-GCM, encrypted export | No server, no login approval or risk scoring |
| Ente Auth | Cross-platform, end-to-end encrypted sync | Code generator; no risk-based login approval |
| 2FAuth (self-hosted web), Authelia (2FA/SSO gateway) | Self-hosted TOTP manager; 2FA in front of services | Descriptions from background knowledge, not verified in this search |
| Microsoft Authenticator, Duo Mobile | Number matching, app name and location context | Closed, tied to their identity platforms |
| RBA for OpenStack (Wiefling et al.) | Open-source RBA | Targets cloud login, not an authenticator app with approval prompts |

I did not find an open-source authenticator backend that combines per-login risk
scoring, impossible-travel checks and number-matched approval from a trusted device.
That is a statement about this one search, not a proven gap; widen the search
(Google Scholar, IEEE Xplore, GitHub topics) before claiming novelty.

## 6. What this implementation does and does not claim

- Risk score, impossible travel and number matching are implemented in
  `services/riskService.js`, `utils/geo.js`, `controllers/authController.js` and `controllers/approvalController.js`.
- It defends against MFA fatigue (number matching, wrong-pick limit, request rate limit,
  single-use tokens) and against stolen passwords used from unfamiliar devices.
- It is not phishing-resistant in the FIDO2 sense. A live relay site can pass the number
  to a victim. Showing the requesting site and location helps an attentive user, and
  the Origin check catches direct API abuse, but a transparent proxy defeats both.
  WebAuthn (a stub in `fraudshield_auth`) is the next step.
- Weights and thresholds are hand-set, not learned or evaluated on data.
