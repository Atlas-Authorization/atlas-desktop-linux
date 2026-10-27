package agent

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // RFC 6238 TOTP is HMAC-SHA1
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/scrypt"
)

// JWK is a P-256 public key.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// DeviceKey is the workstation's ES256 key. On Linux it is a software key held in a root-only file (see SECURITY.md):
// the same key signs requests and opens offline bundles (ECDH), so no separate seal key is enrolled.
type DeviceKey struct{ k *ecdsa.PrivateKey }

const keyFile = "device.key"

// GenerateDeviceKey creates and stores a new key. It refuses to replace an existing one.
func GenerateDeviceKey(s *Store) (*DeviceKey, error) {
	if _, ok := s.Get(keyFile); ok {
		return nil, errors.New("a device key already exists; remove it first to re-enrol")
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil, err
	}
	if err := s.Set(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})); err != nil {
		return nil, err
	}
	return &DeviceKey{k}, nil
}

func OpenDeviceKey(s *Store) (*DeviceKey, error) {
	b, ok := s.Get(keyFile)
	if !ok {
		return nil, errNoKey
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("device key unreadable")
	}
	pk, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, errors.New("device key unreadable")
	}
	k, ok := pk.(*ecdsa.PrivateKey)
	if !ok || k.Curve != elliptic.P256() {
		return nil, errors.New("device key is not P-256")
	}
	return &DeviceKey{k}, nil
}

// KeyFromJWK builds a key from a private JWK (test vectors).
func KeyFromJWK(x, y, d string) (*DeviceKey, error) {
	xb, e1 := unb64u(x)
	yb, e2 := unb64u(y)
	db, e3 := unb64u(d)
	if e1 != nil || e2 != nil || e3 != nil {
		return nil, errors.New("bad jwk")
	}
	k := &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(xb), Y: new(big.Int).SetBytes(yb)}, D: new(big.Int).SetBytes(db)}
	return &DeviceKey{k}, nil
}

func pad32(b *big.Int) []byte { out := make([]byte, 32); b.FillBytes(out); return out }

func (d *DeviceKey) PublicJWK() JWK {
	return JWK{Kty: "EC", Crv: "P-256", X: b64u(pad32(d.k.X)), Y: b64u(pad32(d.k.Y))}
}

// Sign returns the IEEE P1363 (r||s) ES256 signature over the UTF-8 message, base64url.
func (d *DeviceKey) Sign(msg string) (string, error) {
	h := sha256.Sum256([]byte(msg))
	r, s, err := ecdsa.Sign(rand.Reader, d.k, h[:])
	if err != nil {
		return "", err
	}
	return b64u(append(pad32(r), pad32(s)...)), nil
}

// VerifyP1363 checks an ES256 signature (used by tests against the server's vectors).
func VerifyP1363(pub JWK, msg, sigB64u string) bool {
	xb, e1 := unb64u(pub.X)
	yb, e2 := unb64u(pub.Y)
	sig, e3 := unb64u(sigB64u)
	if e1 != nil || e2 != nil || e3 != nil || len(sig) != 64 {
		return false
	}
	h := sha256.Sum256([]byte(msg))
	k := ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(xb), Y: new(big.Int).SetBytes(yb)}
	return ecdsa.Verify(&k, h[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:]))
}

// ECDH is the raw shared secret (X coordinate) with an uncompressed peer point.
func (d *DeviceKey) ECDH(peerPoint []byte) ([]byte, error) {
	priv, err := d.k.ECDH()
	if err != nil {
		return nil, err
	}
	pub, err := ecdh.P256().NewPublicKey(peerPoint)
	if err != nil {
		return nil, err
	}
	return priv.ECDH(pub)
}

// ---- offline bundle ---------------------------------------------------------------------------------------------------

type Bundle struct {
	BundleID   string `json:"bundle_id"`
	Generation int64  `json:"generation"`
	IssuedAt   int64  `json:"issued_at"`
	ExpiresAt  int64  `json:"expires_at"`
	Sealed     string `json:"sealed"`
	Mac        string `json:"mac"`
}

// MacValid: base64url(HMAC-SHA256(mac key, "atlas-desktop-bundle:v1:" device ":" bundle ":" generation ":" expires_at ":" sealed)), constant time.
func (b *Bundle) MacValid(macKey []byte, deviceID string) bool {
	tag, err := unb64u(b.Mac)
	if err != nil {
		return false
	}
	m := hmac.New(sha256.New, macKey)
	fmt.Fprintf(m, "atlas-desktop-bundle:v1:%s:%s:%d:%d:%s", deviceID, b.BundleID, b.Generation, b.ExpiresAt, b.Sealed)
	return hmac.Equal(m.Sum(nil), tag)
}

type ScryptVerifier struct {
	Alg  string `json:"alg"`
	N    int    `json:"N"`
	R    int    `json:"r"`
	P    int    `json:"p"`
	Salt string `json:"salt"`
	Hash string `json:"hash"`
}

// Verify is constant time and bounded so a hostile bundle cannot ask for gigabytes (same limits as the macOS agent).
func (v *ScryptVerifier) Verify(pin string) bool {
	salt, e1 := unb64u(v.Salt)
	want, e2 := unb64u(v.Hash)
	if v.Alg != "scrypt" || e1 != nil || e2 != nil || len(want) != 32 {
		return false
	}
	if v.N < 2 || v.N&(v.N-1) != 0 || v.R < 1 || v.P < 1 || v.N*v.R > 1<<18 || v.P*v.R > 64 {
		return false
	}
	got, err := scrypt.Key([]byte(pin), salt, v.N, v.R, v.P, 32)
	return err == nil && ctEqual(got, want)
}

type TOTPSeed struct {
	Secret    string `json:"secret"`
	Digits    int    `json:"digits"`
	Period    int    `json:"period"`
	Algorithm string `json:"algorithm"`
}

type BundlePlain struct {
	V           int             `json:"v"`
	BundleID    string          `json:"bundle_id"`
	DeviceID    string          `json:"device_id"`
	UserID      string          `json:"user_id"`
	Generation  int64           `json:"generation"`
	IssuedAt    int64           `json:"issued_at"`
	ExpiresAt   int64           `json:"expires_at"`
	PinRequired bool            `json:"pin_required"`
	Pin         *ScryptVerifier `json:"pin"`
	TOTP        TOTPSeed        `json:"totp"`
}

// Open decrypts sealed = 0x01 || ephemeral point (65) || iv (12) || ciphertext || tag (16): ECDH with the device key,
// HKDF-SHA256(salt = ephemeral point, info = "atlas-desktop-offline-bundle-v1"), AES-256-GCM.
func (b *Bundle) Open(k *DeviceKey) (*BundlePlain, error) {
	raw, err := unb64u(b.Sealed)
	if err != nil || len(raw) < 1+65+12+16 || raw[0] != 1 {
		return nil, errors.New("malformed sealed bundle")
	}
	eph, iv, rest := raw[1:66], raw[66:78], raw[78:]
	secret, err := k.ECDH(eph)
	if err != nil {
		return nil, errors.New("bundle open failed")
	}
	key := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, secret, eph, []byte("atlas-desktop-offline-bundle-v1")), key); err != nil {
		return nil, err
	}
	blk, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(blk)
	plain, err := gcm.Open(nil, iv, rest, nil) // Go expects ciphertext||tag, which is the wire layout
	if err != nil {
		return nil, errors.New("bundle open failed")
	}
	var p BundlePlain
	if err := jsonUnmarshal(plain, &p); err != nil || p.V != 1 {
		return nil, errors.New("malformed bundle")
	}
	return &p, nil
}

// ---- TOTP -------------------------------------------------------------------------------------------------------------

func base32Decode(s string) ([]byte, bool) {
	const alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	var out []byte
	bits, acc := 0, 0
	for _, ch := range strings.ToUpper(s) {
		if ch == '=' || ch == ' ' {
			continue
		}
		v := strings.IndexRune(alpha, ch)
		if v < 0 {
			return nil, false
		}
		acc = acc<<5 | v
		bits += 5
		if bits >= 8 {
			bits -= 8
			out = append(out, byte(acc>>bits))
			acc &= (1 << bits) - 1
		}
	}
	return out, true
}

func totpCode(secret []byte, step int64) string {
	var c [8]byte
	binary.BigEndian.PutUint64(c[:], uint64(step))
	m := hmac.New(sha1.New, secret)
	m.Write(c[:])
	sum := m.Sum(nil)
	o := sum[19] & 0x0f
	bin := (uint32(sum[o])&0x7f)<<24 | uint32(sum[o+1])<<16 | uint32(sum[o+2])<<8 | uint32(sum[o+3])
	return fmt.Sprintf("%06d", bin%1000000)
}

func isDigits(s string, lo, hi int) bool {
	if len(s) < lo || len(s) > hi {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// totpVerify accepts the current step +/- 1 that is greater than lastStep and returns the accepted step.
func totpVerify(input string, seed TOTPSeed, nowMs, lastStep int64) (int64, bool) {
	secret, ok := base32Decode(seed.Secret)
	if !ok || !strings.EqualFold(seed.Algorithm, "SHA1") || seed.Digits != 6 || seed.Period <= 0 || !isDigits(input, 6, 6) {
		return 0, false
	}
	cur := nowMs / 1000 / int64(seed.Period)
	hit, found := int64(0), false
	for _, step := range []int64{cur - 1, cur, cur + 1} {
		if step > lastStep && ctEqual([]byte(totpCode(secret, step)), []byte(input)) {
			hit, found = step, true
		}
	}
	return hit, found
}
