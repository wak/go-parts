package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func GenerateKeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return generateKeyPair(rand.Reader)
}

func generateKeyPair(random io.Reader) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(random)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate key: %v", err)
	}
	return publicKey, privateKey, nil
}

func PublicKeyFromPrivateKey(privateKey ed25519.PrivateKey) ed25519.PublicKey {
	return privateKey.Public().(ed25519.PublicKey)

}

var marshalPKIXPublicKey = x509.MarshalPKIXPublicKey

func PublicKeyToPem(pub ed25519.PublicKey) ([]byte, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid input %d != %d", len(pub), ed25519.PublicKeySize)
	}

	der, err := marshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}

	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	}

	return pem.EncodeToMemory(block), nil
}

var parsePKIXPublicKey = x509.ParsePKIXPublicKey

func ParsePublicKeyPem(publicKeyPEM []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(publicKeyPEM)
	if block == nil {
		return nil, errors.New("failed to decode PEM")
	}
	if block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("PEM type is not PUBLIC KEY: %s", block.Type)
	}

	key, err := parsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	pub, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("not an ed25519 public key")
	}

	return pub, nil
}

var marshalPKCS8PrivateKey = x509.MarshalPKCS8PrivateKey

func PrivateKeyToPem(priv ed25519.PrivateKey) ([]byte, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("Invalid input %d != %d", len(priv), ed25519.PrivateKeySize)
	}

	der, err := marshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}

	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	}
	return pem.EncodeToMemory(block), nil
}

var parsePKCS8PrivateKey = x509.ParsePKCS8PrivateKey

func ParsePrivateKeyPem(privateKeyPEM []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return nil, errors.New("failed to decode PEM")
	}
	if block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("PEM type is not PRIVATE KEY: %s", block.Type)
	}

	key, err := parsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("Not an ed25519 private key")
	}

	return priv, nil
}

func CreateKeyIdFromPublicKey(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func CreateKeyIdFromPrivateKey(pri ed25519.PrivateKey) string {
	sum := sha256.Sum256(PublicKeyFromPrivateKey(pri))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

type KeyStore struct {
	privateKeyMap map[string]ed25519.PrivateKey
	publicKeyMap  map[string]ed25519.PublicKey
}

func NewKeyStore() *KeyStore {
	return &KeyStore{
		privateKeyMap: make(map[string]ed25519.PrivateKey),
		publicKeyMap:  make(map[string]ed25519.PublicKey),
	}
}

func NewKeyStoreFromFS(fsys fs.FS) (*KeyStore, error) {
	store := NewKeyStore()
	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		data, err := fs.ReadFile(fsys, path)
		if err != nil {
			return err
		}
		priKey, err := ParsePrivateKeyPem(data)
		if err != nil {
			return err
		}
		store.AddPrivateKey(priKey)
		return nil
	})
	return store, err
}

func (s *KeyStore) AddPrivateKey(privateKey ed25519.PrivateKey) {
	keyId := CreateKeyIdFromPrivateKey(privateKey)
	s.privateKeyMap[keyId] = privateKey
	s.publicKeyMap[keyId] = PublicKeyFromPrivateKey(privateKey)
}

func (s *KeyStore) AddPublicKey(publicKey ed25519.PublicKey) {
	keyId := CreateKeyIdFromPublicKey(publicKey)
	s.publicKeyMap[keyId] = publicKey
}

func (s *KeyStore) GetPrivateKey(keyId string) (ed25519.PrivateKey, bool) {
	entry, ok := s.privateKeyMap[keyId]
	if ok {
		return entry, true
	} else {
		return *new(ed25519.PrivateKey), false
	}
}

func (s *KeyStore) GetPublicKey(keyId string) (ed25519.PublicKey, bool) {
	entry, ok := s.publicKeyMap[keyId]

	if ok {
		return entry, true
	} else {
		return *new(ed25519.PublicKey), false
	}
}

func (s *KeyStore) Len() int {
	return len(s.privateKeyMap)
}

type AppClaims struct {
	UserId string `json:"uid"`
	jwt.RegisteredClaims
}

type CreateJwtAppParam struct {
	UserId string `json:"uid"`
}

var signedString = (*jwt.Token).SignedString

func CreateJwt(
	privateKey ed25519.PrivateKey,
	issuer string,
	audience []string,
	subject string,
	appParam CreateJwtAppParam,
) (string, error) {
	claims := AppClaims{
		UserId: appParam.UserId,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   subject,
			Audience:  audience,
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token.Header["kid"] = CreateKeyIdFromPrivateKey(privateKey)

	signed, err := signedString(token, privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign jwt: %w", err)
	}

	return signed, nil
}

func VerifyJwt(
	store *KeyStore,
	tokenString string,
	issuer string,
	audience string,
) (*AppClaims, error) {
	claims := &AppClaims{}

	token, err := jwt.ParseWithClaims(
		tokenString,
		claims,
		func(token *jwt.Token) (any, error) {
			if token.Method.Alg() != jwt.SigningMethodEdDSA.Alg() {
				return nil, fmt.Errorf("unexpected alg")
			}
			kid, _ := token.Header["kid"].(string)
			priKey, ok := store.GetPublicKey(kid)
			if !ok {
				return nil, fmt.Errorf("unknown kid: %s", kid)
			}
			return priKey, nil
		},
		jwt.WithExpirationRequired(),
		jwt.WithAllAudiences(audience),
		jwt.WithIssuer(issuer),
		jwt.WithIssuedAt(),
	)
	if err != nil || !token.Valid {
		return nil, fmt.Errorf("parse failed: %w", err)
	}

	return claims, nil
}
