// OffGrid Pay chaincode for DRUNIX (Hyperledger Fabric 2.5 compatible)
// Token lifecycle: mint -> offline transfer -> settle -> (dispute / revoke / expire)
//
// Build:  go mod init offgridpay && go get github.com/hyperledger/fabric-contract-api-go/contractapi
// Deploy: package and install like any Fabric Go chaincode on the DRUNIX test network.

package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// ---------- Data models ----------

// OfflineToken is a pre-funded unit of value bound to one device key.
type OfflineToken struct {
	DocType   string `json:"docType"` // "token"
	TokenID   string `json:"tokenId"`
	OwnerID   string `json:"ownerId"`   // device / wallet ID of current holder
	Amount    int64  `json:"amount"`    // in paise
	IssuerOrg string `json:"issuerOrg"` // bank MSP that locked funds
	Status    string `json:"status"`    // ACTIVE, SPENT, SETTLED, EXPIRED, FROZEN
	ExpiresAt int64  `json:"expiresAt"` // unix seconds
}

// Device holds the public key and last-seen counter for replay protection.
type Device struct {
	DocType     string `json:"docType"` // "device"
	DeviceID    string `json:"deviceId"`
	PublicKey   string `json:"publicKey"` // PEM, ECDSA P-256
	LastCounter int64  `json:"lastCounter"`
	Revoked     bool   `json:"revoked"`
}

// OfflinePayment is what the payer's phone signs and hands to the payee offline.
type OfflinePayment struct {
	PaymentID string   `json:"paymentId"`
	PayerID   string   `json:"payerId"`
	PayeeID   string   `json:"payeeId"`
	TokenIDs  []string `json:"tokenIds"`
	Amount    int64    `json:"amount"`
	Counter   int64    `json:"counter"`   // monotonically increasing per payer device
	Timestamp int64    `json:"timestamp"` // payer device clock
	Signature string   `json:"signature"` // base64 ASN.1 ECDSA over the payload hash
}

// Dispute records a contested payment.
type Dispute struct {
	DocType   string `json:"docType"` // "dispute"
	PaymentID string `json:"paymentId"`
	RaisedBy  string `json:"raisedBy"`
	Reason    string `json:"reason"`
	Status    string `json:"status"` // OPEN, RESOLVED
}

// Private details (payer/payee identity, phone numbers) go to a KeyDB-backed
// private data collection, visible only to the two banks involved.
type PaymentPrivateDetails struct {
	PaymentID   string `json:"paymentId"`
	PayerVPA    string `json:"payerVpa"`
	PayeeVPA    string `json:"payeeVpa"`
	PayeeBankAC string `json:"payeeBankRef"` // reference only, never full account number
}

const privateCollection = "collectionBankPrivate"

// Offline limits (align with RBI offline payment framework; adjust as needed)
const (
	maxPerPayment    int64 = 50000  // ₹500 in paise
	maxWalletBalance int64 = 500000 // ₹5,000 in paise
)

type OffGridContract struct {
	contractapi.Contract
}

// ---------- Device registration ----------

func (c *OffGridContract) RegisterDevice(ctx contractapi.TransactionContextInterface, deviceID, publicKeyPEM string) error {
	exists, err := c.keyExists(ctx, deviceKey(deviceID))
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("device %s already registered", deviceID)
	}
	if _, err := parsePublicKey(publicKeyPEM); err != nil {
		return fmt.Errorf("invalid public key: %v", err)
	}
	d := Device{DocType: "device", DeviceID: deviceID, PublicKey: publicKeyPEM}
	return putJSON(ctx, deviceKey(deviceID), d)
}

// ---------- Mint (online load) ----------

// MintOfflineToken is called by the issuer bank after locking funds in the user's account.
func (c *OffGridContract) MintOfflineToken(ctx contractapi.TransactionContextInterface, tokenID, ownerID string, amount int64, validDays int) error {
	issuer, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return err
	}
	if amount <= 0 || amount > maxWalletBalance {
		return fmt.Errorf("amount out of allowed range")
	}
	if exists, _ := c.keyExists(ctx, tokenKey(tokenID)); exists {
		return fmt.Errorf("token %s already exists", tokenID)
	}
	ts, _ := ctx.GetStub().GetTxTimestamp()
	t := OfflineToken{
		DocType:   "token",
		TokenID:   tokenID,
		OwnerID:   ownerID,
		Amount:    amount,
		IssuerOrg: issuer,
		Status:    "ACTIVE",
		ExpiresAt: ts.Seconds + int64(validDays)*86400,
	}
	return putJSON(ctx, tokenKey(tokenID), t)
}

// ---------- Settle (sync after reconnecting) ----------

// SettleOfflinePayment records one offline payment uploaded by either phone.
// MVCC on the token keys guarantees a token can only be spent once: if two
// payments using the same token arrive, the second fails validation at commit.
func (c *OffGridContract) SettleOfflinePayment(ctx contractapi.TransactionContextInterface, paymentJSON string) error {
	var p OfflinePayment
	if err := json.Unmarshal([]byte(paymentJSON), &p); err != nil {
		return fmt.Errorf("bad payment payload: %v", err)
	}
	if p.Amount <= 0 || p.Amount > maxPerPayment {
		return fmt.Errorf("amount exceeds offline per-payment limit")
	}
	if exists, _ := c.keyExists(ctx, paymentKey(p.PaymentID)); exists {
		return fmt.Errorf("payment %s already settled", p.PaymentID)
	}

	// 1. Payer device must exist, be active, and counter must move forward (replay protection)
	var dev Device
	if err := getJSON(ctx, deviceKey(p.PayerID), &dev); err != nil {
		return fmt.Errorf("unknown payer device")
	}
	if dev.Revoked {
		return fmt.Errorf("payer device revoked")
	}
	if p.Counter <= dev.LastCounter {
		return fmt.Errorf("replayed or out-of-order counter: possible double-spend")
	}

	// 2. Verify payer signature (DRUNIX stateless validation service can also
	//    pre-check this off-peer; repeated here for defence in depth)
	if err := verifyPaymentSignature(dev.PublicKey, p); err != nil {
		return err
	}

	// 3. Check tokens: owned by payer, active, unexpired, and sum to amount
	ts, _ := ctx.GetStub().GetTxTimestamp()
	var total int64
	tokens := make([]OfflineToken, 0, len(p.TokenIDs))
	for _, id := range p.TokenIDs {
		var t OfflineToken
		if err := getJSON(ctx, tokenKey(id), &t); err != nil {
			return fmt.Errorf("token %s not found", id)
		}
		if t.OwnerID != p.PayerID || t.Status != "ACTIVE" {
			return fmt.Errorf("token %s not spendable by payer (double-spend attempt?)", id)
		}
		if t.ExpiresAt < ts.Seconds {
			return fmt.Errorf("token %s expired", id)
		}
		total += t.Amount
		tokens = append(tokens, t)
	}
	if total != p.Amount {
		return fmt.Errorf("token total %d does not match payment amount %d", total, p.Amount)
	}

	// 4. Mark tokens spent and record the payment
	for _, t := range tokens {
		t.Status = "SPENT"
		t.OwnerID = p.PayeeID
		if err := putJSON(ctx, tokenKey(t.TokenID), t); err != nil {
			return err
		}
	}
	dev.LastCounter = p.Counter
	if err := putJSON(ctx, deviceKey(p.PayerID), dev); err != nil {
		return err
	}
	if err := putJSON(ctx, paymentKey(p.PaymentID), p); err != nil {
		return err
	}

	// 5. Optional private details from transient map -> KeyDB private collection
	transient, _ := ctx.GetStub().GetTransient()
	if priv, ok := transient["private"]; ok {
		if err := ctx.GetStub().PutPrivateData(privateCollection, paymentKey(p.PaymentID), priv); err != nil {
			return err
		}
	}

	return ctx.GetStub().SetEvent("PaymentSettled", []byte(p.PaymentID))
}

// ---------- Disputes and fraud handling ----------

func (c *OffGridContract) RaiseDispute(ctx contractapi.TransactionContextInterface, paymentID, raisedBy, reason string) error {
	if exists, _ := c.keyExists(ctx, paymentKey(paymentID)); !exists {
		return fmt.Errorf("payment %s not found", paymentID)
	}
	d := Dispute{DocType: "dispute", PaymentID: paymentID, RaisedBy: raisedBy, Reason: reason, Status: "OPEN"}
	return putJSON(ctx, disputeKey(paymentID), d)
}

func (c *OffGridContract) ResolveDispute(ctx contractapi.TransactionContextInterface, paymentID string) error {
	var d Dispute
	if err := getJSON(ctx, disputeKey(paymentID), &d); err != nil {
		return err
	}
	d.Status = "RESOLVED"
	return putJSON(ctx, disputeKey(paymentID), d)
}

// RevokeDevice is called when a double-spend attempt is detected; the key is
// blocked network-wide and all its remaining tokens are frozen.
func (c *OffGridContract) RevokeDevice(ctx contractapi.TransactionContextInterface, deviceID string) error {
	var d Device
	if err := getJSON(ctx, deviceKey(deviceID), &d); err != nil {
		return err
	}
	d.Revoked = true
	if err := putJSON(ctx, deviceKey(deviceID), d); err != nil {
		return err
	}
	// Freeze remaining active tokens (CouchDB/YugabyteDB rich query)
	query := fmt.Sprintf(`{"selector":{"docType":"token","ownerId":"%s","status":"ACTIVE"}}`, deviceID)
	iter, err := ctx.GetStub().GetQueryResult(query)
	if err != nil {
		return err
	}
	defer iter.Close()
	for iter.HasNext() {
		kv, err := iter.Next()
		if err != nil {
			return err
		}
		var t OfflineToken
		_ = json.Unmarshal(kv.Value, &t)
		t.Status = "FROZEN"
		if err := putJSON(ctx, kv.Key, t); err != nil {
			return err
		}
	}
	return nil
}

// RedeemExpired returns value of expired, unspent tokens to the owner's bank account.
func (c *OffGridContract) RedeemExpired(ctx contractapi.TransactionContextInterface, tokenID string) error {
	var t OfflineToken
	if err := getJSON(ctx, tokenKey(tokenID), &t); err != nil {
		return err
	}
	ts, _ := ctx.GetStub().GetTxTimestamp()
	if t.Status != "ACTIVE" || t.ExpiresAt > ts.Seconds {
		return fmt.Errorf("token not eligible for redemption")
	}
	t.Status = "EXPIRED"
	return putJSON(ctx, tokenKey(tokenID), t)
}

// ---------- Queries ----------

func (c *OffGridContract) GetToken(ctx contractapi.TransactionContextInterface, tokenID string) (*OfflineToken, error) {
	var t OfflineToken
	err := getJSON(ctx, tokenKey(tokenID), &t)
	return &t, err
}

func (c *OffGridContract) GetPayment(ctx contractapi.TransactionContextInterface, paymentID string) (*OfflinePayment, error) {
	var p OfflinePayment
	err := getJSON(ctx, paymentKey(paymentID), &p)
	return &p, err
}

// ---------- Helpers ----------

func tokenKey(id string) string   { return "TOKEN_" + id }
func deviceKey(id string) string  { return "DEVICE_" + id }
func paymentKey(id string) string { return "PAY_" + id }
func disputeKey(id string) string { return "DISPUTE_" + id }

func (c *OffGridContract) keyExists(ctx contractapi.TransactionContextInterface, key string) (bool, error) {
	b, err := ctx.GetStub().GetState(key)
	return b != nil, err
}

func putJSON(ctx contractapi.TransactionContextInterface, key string, v interface{}) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return ctx.GetStub().PutState(key, b)
}

func getJSON(ctx contractapi.TransactionContextInterface, key string, v interface{}) error {
	b, err := ctx.GetStub().GetState(key)
	if err != nil {
		return err
	}
	if b == nil {
		return fmt.Errorf("%s not found", key)
	}
	return json.Unmarshal(b, v)
}

func parsePublicKey(pemStr string) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("no PEM block")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an ECDSA key")
	}
	return ecPub, nil
}

// signedPayload is the canonical byte string the phone signs (everything except the signature).
func signedPayload(p OfflinePayment) []byte {
	cp := p
	cp.Signature = ""
	b, _ := json.Marshal(cp)
	return b
}

func verifyPaymentSignature(pubPEM string, p OfflinePayment) error {
	pub, err := parsePublicKey(pubPEM)
	if err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(p.Signature)
	if err != nil {
		return fmt.Errorf("bad signature encoding")
	}
	hash := sha256.Sum256(signedPayload(p))
	if !ecdsa.VerifyASN1(pub, hash[:], sig) {
		return fmt.Errorf("invalid payer signature")
	}
	return nil
}

func main() {
	cc, err := contractapi.NewChaincode(&OffGridContract{})
	if err != nil {
		panic(fmt.Sprintf("error creating chaincode: %v", err))
	}
	if err := cc.Start(); err != nil {
		panic(fmt.Sprintf("error starting chaincode: %v", err))
	}
}
