# OffGrid Pay

**Secure offline digital payments for India's no-network zones, settled on DRUNIX.**

Team Zyro · DRUNIX Hackathon 2026 (NPCI × Citi) · Theme: Financial Inclusion

---

## The problem

UPI needs the payer's phone and the bank systems to be online at the same moment. A large share of everyday commerce in India happens where that is not possible: weekly rural shandies, hill and forest areas, fishing harbours, border villages, trains, basements and disaster-hit regions. When the network fails, payments fail and people fall back to cash.

Existing offline options either need NFC hardware that most low-cost phones lack, or cannot reliably prevent the same balance from being spent twice.

## Our solution

OffGrid Pay converts a small, pre-funded amount into **cryptographically signed offline tokens** recorded on a **DRUNIX permissioned ledger**. Tokens move phone-to-phone with zero internet, using QR codes or Bluetooth, and are settled on the ledger whenever either party reconnects, by mobile data or by SMS.

### How it works

1. **Load (online):** the user moves a small amount from their bank account to an OffGrid wallet. The bank locks the funds and mints offline tokens bound to the device's public key.
2. **Pay (offline):** the payer's app builds a payment with token IDs, amount, payee ID, timestamp and a device counter, signs it with a key in the phone's hardware keystore, and passes it by QR or Bluetooth.
3. **Verify (offline):** the merchant's app checks the signature, counter and limits, then shows "Payment received".
4. **Sync:** queued payments upload when data returns, or are sent by SMS to a bank gateway shortcode.
5. **Settle (DRUNIX):** Lite Peers endorse, the stateless validation service checks signatures and counters, and Committing Peers' MVCC checks make sure each token is spent only once. Banks then settle to the merchant's account.

### Double-spend protection

| Layer | What it does |
|---|---|
| Device counter | Every payment carries a counter that must increase, so replayed payments are rejected |
| Hardware-backed signature | Only the registered device can sign its own payments |
| MVCC on token keys | Two payments using the same token cannot both commit |
| Revocation and reserve | A cheating device is revoked network-wide; the honest merchant is paid from a pooled reserve |
| Bounded limits | Per-payment and wallet caps, plus token expiry, cap the loss from any one device |

## DRUNIX components used

| Component | Role in OffGrid Pay |
|---|---|
| Lite Peers / Committing Peers | Lite Peers scale out to absorb sync bursts when markets reconnect; Committing Peers validate and commit |
| Stateless validation service | Verifies device signatures and counters independently of the peers |
| YugabyteDB state database | SQL queries for settlement, fraud analytics and merchant dashboards |
| KeyDB transient store / private data | Keeps payer and payee details visible only to the banks involved |
| Chaincode (Go) | Token lifecycle: register, mint, settle, dispute, revoke, expire |
| Multi-organisation network | Issuer banks, acquirer banks, NPCI and a regulator observer each run nodes |
| Falcon | Deploys and manages the network on Kubernetes |

## Repository structure

```
offgrid-pay/
├── chaincode/
│   └── offgridpay_chaincode.go   # Go chaincode for DRUNIX / Fabric 2.5
├── docs/
│   └── architecture.png          # System architecture diagram
└── README.md
```

## Chaincode functions

| Function | Purpose |
|---|---|
| `RegisterDevice` | Stores a device's ECDSA P-256 public key |
| `MintOfflineToken` | Called by the issuer bank after locking funds |
| `SettleOfflinePayment` | Verifies and settles an offline payment uploaded at sync |
| `RaiseDispute` / `ResolveDispute` | Records and closes payment disputes |
| `RevokeDevice` | Blocks a cheating device and freezes its tokens |
| `RedeemExpired` | Returns value of unspent, expired tokens |
| `GetToken` / `GetPayment` | Read queries |

## Tech stack

- **Ledger:** DRUNIX (Hyperledger Fabric 2.5 compatible), Raft ordering
- **Chaincode:** Go, `fabric-contract-api-go`
- **Mobile app:** Flutter (Android first), Android Keystore, ECDSA P-256, SQLite offline queue, QR and Bluetooth Low Energy
- **Backend:** Go sync gateway with Fabric Gateway SDK, SMS gateway integration, REST APIs
- **Fraud scoring:** Isolation Forest / XGBoost at sync time
- **Deployment:** Kubernetes with NPCI Falcon

## Getting started (chaincode)

```bash
cd chaincode
go mod init offgridpay
go get github.com/hyperledger/fabric-contract-api-go/contractapi
go build ./...
```

Package and install the chaincode on a DRUNIX / Fabric test network as you would any Go chaincode.

## Roadmap (21 days)

| Phase | Days | Deliverable |
|---|---|---|
| 1 | 1–7 | DRUNIX test network with two banks and NPCI; chaincode for mint, settle, dispute, revoke |
| 2 | 8–14 | Android app with offline QR payments and sync gateway |
| 3 | 15–21 | Double-spend tests and a live demo with about 10 vendors at a local market |

## Status

Concept, architecture and chaincode design are complete. The prototype is under development.

## License

Apache 2.0
