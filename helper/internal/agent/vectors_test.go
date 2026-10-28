package agent

import (
	"encoding/json"
	"os"
	"testing"
)

type vectors struct {
	DevicePrivate struct{ X, Y, D string } `json:"device_private_jwk"`
	MacKey        string                   `json:"mac_key_b64u"`
	Bundle        struct {
		DeviceID   string      `json:"device_id"`
		BundleID   string      `json:"bundle_id"`
		Generation int64       `json:"generation"`
		ExpiresAt  int64       `json:"expires_at"`
		Sealed     string      `json:"sealed"`
		Mac        string      `json:"mac"`
		Plaintext  BundlePlain `json:"plaintext"`
	} `json:"bundle"`
	Pin struct {
		Value    string         `json:"value"`
		Verifier ScryptVerifier `json:"verifier"`
		Wrong    string         `json:"wrong"`
	} `json:"pin"`
	TOTP struct {
		Secret string `json:"secret"`
		Times  []struct {
			Unix int64  `json:"unix"`
			Code string `json:"code"`
		} `json:"times"`
	} `json:"totp"`
	Signed struct {
		Purpose    string `json:"purpose"`
		InstanceID string `json:"instance_id"`
		KeyID      string `json:"key_id"`
		Nonce      string `json:"nonce"`
		Message    string `json:"message"`
		Signature  string `json:"signature_p1363_b64u"`
	} `json:"signed_message"`
	Public JWK `json:"device_public_jwk"`
}

func loadVectors(t *testing.T) (*vectors, *DeviceKey) {
	t.Helper()
	b, err := os.ReadFile("testdata/protocol-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	k, err := KeyFromJWK(v.DevicePrivate.X, v.DevicePrivate.Y, v.DevicePrivate.D)
	if err != nil {
		t.Fatal(err)
	}
	return &v, k
}

func TestVectorsBundleMacOpenPinTotp(t *testing.T) {
	v, key := loadVectors(t)
	mk, _ := unb64u(v.MacKey)
	b := &Bundle{BundleID: v.Bundle.BundleID, Generation: v.Bundle.Generation, ExpiresAt: v.Bundle.ExpiresAt, Sealed: v.Bundle.Sealed, Mac: v.Bundle.Mac}
	if !b.MacValid(mk, v.Bundle.DeviceID) {
		t.Fatal("server MAC did not verify")
	}
	if b.MacValid(mk, "ddv_OTHER") {
		t.Fatal("MAC must bind the device id")
	}
	bad := *b
	bad.Generation++
	if bad.MacValid(mk, v.Bundle.DeviceID) {
		t.Fatal("MAC must bind the generation")
	}
	p, err := b.Open(key)
	if err != nil {
		t.Fatal(err)
	}
	if p.BundleID != v.Bundle.Plaintext.BundleID || p.DeviceID != v.Bundle.DeviceID || p.UserID != v.Bundle.Plaintext.UserID || p.ExpiresAt != v.Bundle.ExpiresAt || !p.PinRequired || p.TOTP.Secret != v.TOTP.Secret {
		t.Fatalf("plaintext mismatch: %+v", p)
	}
	if !p.Pin.Verify(v.Pin.Value) || p.Pin.Verify(v.Pin.Wrong) || p.Pin.Verify("") {
		t.Fatal("pin verifier wrong")
	}
	// A different key cannot open it.
	other, _ := GenerateDeviceKey(newStore(t))
	if _, err := b.Open(other); err == nil {
		t.Fatal("opened with the wrong key")
	}
	// Tampered ciphertext is rejected.
	raw, _ := unb64u(b.Sealed)
	raw[len(raw)-20] ^= 1
	tam := *b
	tam.Sealed = b64u(raw)
	if _, err := tam.Open(key); err == nil {
		t.Fatal("tampered bundle opened")
	}
	for _, tm := range v.TOTP.Times {
		sec, _ := base32Decode(v.TOTP.Secret)
		if got := totpCode(sec, tm.Unix/30); got != tm.Code {
			t.Fatalf("totp at %d: got %s want %s", tm.Unix, got, tm.Code)
		}
	}
}

func TestVectorsSignedMessage(t *testing.T) {
	v, key := loadVectors(t)
	msg := SignedMessage(v.Signed.Purpose, v.Signed.InstanceID, v.Signed.KeyID, v.Signed.Nonce, nil)
	if msg != v.Signed.Message {
		t.Fatalf("message %q != %q", msg, v.Signed.Message)
	}
	if !VerifyP1363(v.Public, msg, v.Signed.Signature) {
		t.Fatal("server vector signature does not verify")
	}
	mine, err := key.Sign(msg)
	if err != nil || !VerifyP1363(v.Public, msg, mine) {
		t.Fatal("own signature does not verify")
	}
	if VerifyP1363(v.Public, msg+"x", mine) {
		t.Fatal("signature verified for a different message")
	}
	if key.PublicJWK() != v.Public {
		t.Fatalf("jwk %+v != %+v", key.PublicJWK(), v.Public)
	}
}

func TestTotpWindowAndReplay(t *testing.T) {
	v, _ := loadVectors(t)
	seed := TOTPSeed{Secret: v.TOTP.Secret, Digits: 6, Period: 30, Algorithm: "SHA1"}
	now := int64(1800000000000)
	step, ok := totpVerify("877905", seed, now, -1)
	if !ok {
		t.Fatal("current code rejected")
	}
	if _, ok := totpVerify("877905", seed, now, step); ok {
		t.Fatal("replayed step accepted")
	}
	if _, ok := totpVerify("000000", seed, now, -1); ok {
		t.Fatal("wrong code accepted")
	}
	if _, ok := totpVerify("87790", seed, now, -1); ok {
		t.Fatal("short code accepted")
	}
	if _, ok := totpVerify("877905", seed, now+5*60_000, -1); ok {
		t.Fatal("code far outside the window accepted")
	}
}

func TestScryptRejectsHostileParameters(t *testing.T) {
	v, _ := loadVectors(t)
	h := v.Pin.Verifier
	h.N = 1 << 24
	if h.Verify(v.Pin.Value) {
		t.Fatal("huge N accepted")
	}
	h = v.Pin.Verifier
	h.N = 3
	if h.Verify(v.Pin.Value) {
		t.Fatal("non power of two accepted")
	}
}
