# AHP Weight Calculation — Actionability Scoring Instrument

Generated: 2026-09-22T16:01:20+00:00

Method: AHP (Saaty 1-9 scale), column-normalized priority vector; consistency required: CR < 0.10 (Saaty, 1980)

## 1. Category comparison matrix

| Criterion | behavioral | relationship | identity | ioc | network | timeline |
|---|---|---|---|---|---|---|
| **Behavioral / Intent** | **1.000** | **1.000** | **3.000** | **3.000** | **1.000** | **5.000** |
| **Relationship / Process Chain** | **1.000** | **1.000** | **1.000** | **3.000** | **2.000** | **5.000** |
| **Identity** | **0.333** | **1.000** | **1.000** | **1.000** | **1.000** | **5.000** |
| **IOC / Threat Intelligence** | **0.333** | **0.333** | **1.000** | **1.000** | **1.000** | **3.000** |
| **Network** | **1.000** | **0.500** | **1.000** | **1.000** | **1.000** | **3.000** |
| **Timeline / Event Context** | **0.200** | **0.200** | **0.200** | **0.333** | **0.333** | **1.000** |

### Category weights

| Criterion | Weight | lambda max | CI | CR | Consistent |
|---|---:|---:|---:|---:|---|
| Behavioral / Intent | 0.2716 | 4.1565 | 0.0522 | 0.0579 | yes |
| Relationship / Process Chain | 0.2517 | 5.0725 | 0.0181 | 0.0162 | yes |
| Identity | 0.1609 | 5.1283 | 0.0321 | 0.0286 | yes |
| IOC / Threat Intelligence | 0.1182 | 3.0387 | 0.0194 | 0.0334 | yes |
| Network | 0.1538 | 4.1185 | 0.0395 | 0.0439 | yes |
| Timeline / Event Context | 0.0438 | 3.0000 | 0.0000 | 0.0000 | yes |
| **Category matrix (level 1)** | 1.0000 | 6.2462 | 0.0492 | 0.0397 | yes |

## 2. Field comparison matrices and priority vectors

### Behavioral / Intent (`behavioral`)

| | commandLine | currentDirectory | originalFileName | description |
|---|---|---|---|---|
| **commandLine** | 1.0000 | 7.0000 | 7.0000 | 7.0000 |
| **currentDirectory** | 0.1429 | 1.0000 | 1.0000 | 3.0000 |
| **originalFileName** | 0.1429 | 1.0000 | 1.0000 | 3.0000 |
| **description** | 0.1429 | 0.3333 | 0.3333 | 1.0000 |

| Field | Local priority | Global weight | Rank | CR |
|---|---:|---:|---:|---:|
| Command Line (`commandLine`) | 0.6750 | 0.1834 | 1 | 0.0579 |
| Current Directory (`currentDirectory`) | 0.1321 | 0.0359 | 2 | 0.0579 |
| Original File Name (`originalFileName`) | 0.1321 | 0.0359 | 3 | 0.0579 |
| File Description (`description`) | 0.0607 | 0.0165 | 4 | 0.0579 |

lambda max = 4.1565, CI = 0.0522, CR = 0.0579 (consistent)

### Relationship / Process Chain (`relationship`)

| | parentImage | parentCommandLine | parentProcessId | processGuid | parentProcessGuid |
|---|---|---|---|---|---|
| **parentImage** | 1.0000 | 3.0000 | 5.0000 | 7.0000 | 2.0000 |
| **parentCommandLine** | 0.3333 | 1.0000 | 3.0000 | 5.0000 | 1.0000 |
| **parentProcessId** | 0.2000 | 0.3333 | 1.0000 | 1.0000 | 0.3333 |
| **processGuid** | 0.1429 | 0.2000 | 1.0000 | 1.0000 | 0.3333 |
| **parentProcessGuid** | 0.5000 | 1.0000 | 3.0000 | 3.0000 | 1.0000 |

| Field | Local priority | Global weight | Rank | CR |
|---|---:|---:|---:|---:|
| Parent Image (`parentImage`) | 0.4453 | 0.1121 | 1 | 0.0162 |
| Parent Command Line (`parentCommandLine`) | 0.2146 | 0.0540 | 2 | 0.0162 |
| Parent Process ID (`parentProcessId`) | 0.0719 | 0.0181 | 4 | 0.0162 |
| Process GUID (`processGuid`) | 0.0618 | 0.0156 | 5 | 0.0162 |
| Parent Process GUID (`parentProcessGuid`) | 0.2064 | 0.0519 | 3 | 0.0162 |

lambda max = 5.0725, CI = 0.0181, CR = 0.0162 (consistent)

### Identity (`identity`)

| | image | processId | user | hostname | integrityLevel |
|---|---|---|---|---|---|
| **image** | 1.0000 | 3.0000 | 3.0000 | 5.0000 | 7.0000 |
| **processId** | 0.3333 | 1.0000 | 1.0000 | 3.0000 | 5.0000 |
| **user** | 0.3333 | 1.0000 | 1.0000 | 3.0000 | 5.0000 |
| **hostname** | 0.2000 | 0.3333 | 0.3333 | 1.0000 | 3.0000 |
| **integrityLevel** | 0.1429 | 0.2000 | 0.2000 | 0.3333 | 1.0000 |

| Field | Local priority | Global weight | Rank | CR |
|---|---:|---:|---:|---:|
| Process Image (`image`) | 0.4641 | 0.0747 | 1 | 0.0286 |
| Process ID (`processId`) | 0.2017 | 0.0325 | 2 | 0.0286 |
| User Context (`user`) | 0.2017 | 0.0325 | 3 | 0.0286 |
| Hostname (`hostname`) | 0.0888 | 0.0143 | 4 | 0.0286 |
| Integrity Level (`integrityLevel`) | 0.0436 | 0.0070 | 5 | 0.0286 |

lambda max = 5.1283, CI = 0.0321, CR = 0.0286 (consistent)

### IOC / Threat Intelligence (`ioc`)

| | hashes | signatureStatus | company |
|---|---|---|---|
| **hashes** | 1.0000 | 3.0000 | 5.0000 |
| **signatureStatus** | 0.3333 | 1.0000 | 3.0000 |
| **company** | 0.2000 | 0.3333 | 1.0000 |

| Field | Local priority | Global weight | Rank | CR |
|---|---:|---:|---:|---:|
| File Hash (`hashes`) | 0.6333 | 0.0749 | 1 | 0.0334 |
| Signature Status (`signatureStatus`) | 0.2605 | 0.0308 | 2 | 0.0334 |
| Company (`company`) | 0.1062 | 0.0125 | 3 | 0.0334 |

lambda max = 3.0387, CI = 0.0194, CR = 0.0334 (consistent)

### Network (`network`)

| | destinationIp | destinationPort | sourceIp | protocol |
|---|---|---|---|---|
| **destinationIp** | 1.0000 | 3.0000 | 5.0000 | 7.0000 |
| **destinationPort** | 0.3333 | 1.0000 | 3.0000 | 5.0000 |
| **sourceIp** | 0.2000 | 0.3333 | 1.0000 | 3.0000 |
| **protocol** | 0.1429 | 0.2000 | 0.3333 | 1.0000 |

| Field | Local priority | Global weight | Rank | CR |
|---|---:|---:|---:|---:|
| Destination IP (`destinationIp`) | 0.5579 | 0.0858 | 1 | 0.0439 |
| Destination Port (`destinationPort`) | 0.2633 | 0.0405 | 2 | 0.0439 |
| Source IP (`sourceIp`) | 0.1219 | 0.0187 | 3 | 0.0439 |
| Protocol (`protocol`) | 0.0569 | 0.0088 | 4 | 0.0439 |

lambda max = 4.1185, CI = 0.0395, CR = 0.0439 (consistent)

### Timeline / Event Context (`timeline`)

| | eventID | ruleLevel | timestamp |
|---|---|---|---|
| **eventID** | 1.0000 | 1.0000 | 3.0000 |
| **ruleLevel** | 1.0000 | 1.0000 | 3.0000 |
| **timestamp** | 0.3333 | 0.3333 | 1.0000 |

| Field | Local priority | Global weight | Rank | CR |
|---|---:|---:|---:|---:|
| Event ID (`eventID`) | 0.4286 | 0.0188 | 1 | 0.0000 |
| Rule Level (`ruleLevel`) | 0.4286 | 0.0188 | 2 | 0.0000 |
| Timestamp (`timestamp`) | 0.1429 | 0.0063 | 3 | 0.0000 |

lambda max = 3.0000, CI = 0.0000, CR = 0.0000 (consistent)

## 3. Global weights (sorted)

| Global rank | Field | Category | Global weight | Local weight |
|---:|---|---|---:|---:|
| 1 | Command Line (`commandLine`) | Behavioral / Intent | 0.1834 | 0.6750 |
| 2 | Parent Image (`parentImage`) | Relationship / Process Chain | 0.1121 | 0.4453 |
| 3 | Destination IP (`destinationIp`) | Network | 0.0858 | 0.5579 |
| 4 | File Hash (`hashes`) | IOC / Threat Intelligence | 0.0749 | 0.6333 |
| 5 | Process Image (`image`) | Identity | 0.0747 | 0.4641 |
| 6 | Parent Command Line (`parentCommandLine`) | Relationship / Process Chain | 0.0540 | 0.2146 |
| 7 | Parent Process GUID (`parentProcessGuid`) | Relationship / Process Chain | 0.0519 | 0.2064 |
| 8 | Destination Port (`destinationPort`) | Network | 0.0405 | 0.2633 |
| 9 | Original File Name (`originalFileName`) | Behavioral / Intent | 0.0359 | 0.1321 |
| 10 | Current Directory (`currentDirectory`) | Behavioral / Intent | 0.0359 | 0.1321 |
| 11 | User Context (`user`) | Identity | 0.0325 | 0.2017 |
| 12 | Process ID (`processId`) | Identity | 0.0325 | 0.2017 |
| 13 | Signature Status (`signatureStatus`) | IOC / Threat Intelligence | 0.0308 | 0.2605 |
| 14 | Rule Level (`ruleLevel`) | Timeline / Event Context | 0.0188 | 0.4286 |
| 15 | Event ID (`eventID`) | Timeline / Event Context | 0.0188 | 0.4286 |
| 16 | Source IP (`sourceIp`) | Network | 0.0187 | 0.1219 |
| 17 | Parent Process ID (`parentProcessId`) | Relationship / Process Chain | 0.0181 | 0.0719 |
| 18 | File Description (`description`) | Behavioral / Intent | 0.0165 | 0.0607 |
| 19 | Process GUID (`processGuid`) | Relationship / Process Chain | 0.0156 | 0.0618 |
| 20 | Hostname (`hostname`) | Identity | 0.0143 | 0.0888 |
| 21 | Company (`company`) | IOC / Threat Intelligence | 0.0125 | 0.1062 |
| 22 | Protocol (`protocol`) | Network | 0.0088 | 0.0569 |
| 23 | Integrity Level (`integrityLevel`) | Identity | 0.0070 | 0.0436 |
| 24 | Timestamp (`timestamp`) | Timeline / Event Context | 0.0063 | 0.1429 |

## 4. Notes

- `parentProcessGuid` is a **proposed new field** (not present in the
  original notebook hierarchy). It is the strongest lineage pivot because
  Sysmon guarantees it on EID 1 and it survives PID reuse.
- Category and field consistency is enforced by `backend/tests/test_ahp.py`.
- Change pairwise values only in `ahp/matrices.py`, then rerun
  `python -m ahp.run_ahp`.
