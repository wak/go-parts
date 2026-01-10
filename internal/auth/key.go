package auth

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"reflect"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var supportedPublicKeyTypes = map[reflect.Type]struct{}{
	reflect.TypeOf(ed25519.PublicKey{}): {},
	reflect.TypeOf(&rsa.PublicKey{}):    {},
}

var supportedPrivateKeyTypes = map[reflect.Type]struct{}{
	reflect.TypeOf(ed25519.PrivateKey{}): {},
	reflect.TypeOf(&rsa.PrivateKey{}):    {},
}

var randReader = rand.Reader

func GenerateKeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(randReader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate key: %v", err)
	}
	return publicKey, privateKey, nil
}

func GenerateRSAKeyPair() (crypto.Signer, error) {
	signer, err := rsa.GenerateKey(randReader, 2048)
	return signer, err
}

var marshalPKIXPublicKey = x509.MarshalPKIXPublicKey

func PublicKeyToPem(pub crypto.PublicKey) ([]byte, error) {
	if pub == nil {
		return nil, fmt.Errorf("Invalid input: %v", pub)
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

func ParsePublicKeyPem(publicKeyPEM []byte) (crypto.PublicKey, error) {
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

	_, ok := supportedPublicKeyTypes[reflect.TypeOf(key)]
	if ok {
		return key, nil
	} else {
		return nil, fmt.Errorf("unsupported public key type: %T", key)
	}
}

var marshalPKCS8PrivateKey = x509.MarshalPKCS8PrivateKey

func PrivateKeyToPem(signer crypto.Signer) ([]byte, error) {
	der, err := marshalPKCS8PrivateKey(signer)
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

func ParsePrivateKeyPem(privateKeyPEM []byte) (crypto.Signer, error) {
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

	_, ok := supportedPrivateKeyTypes[reflect.TypeOf(key)]
	if ok {
		priv, ok := key.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("private key is not crypto.Signer %T", key)
		}
		return priv, nil
	} else {
		return nil, fmt.Errorf("unsupported private key type: %T", key)
	}
}

func CreateKeyIdFromPublicKey(pub crypto.PublicKey) (string, error) {
	switch pubKey := pub.(type) {
	case ed25519.PublicKey:
		sum := sha256.Sum256(pubKey)
		return base64.RawURLEncoding.EncodeToString(sum[:]), nil
	default:
		return "", fmt.Errorf("failed to create key id: %T", pub)
	}
}

func CreateKeyIdFromSigner(signer crypto.Signer) (string, error) {
	switch priKey := signer.(type) {
	case ed25519.PrivateKey:
		sum := sha256.Sum256(priKey.Public().(ed25519.PublicKey))
		return base64.RawURLEncoding.EncodeToString(sum[:]), nil

	case *rsa.PrivateKey:
		pub := priKey.Public().(*rsa.PublicKey)

		der, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			panic(fmt.Sprintf("failed to marshal rsa public key: %v", err))
		}

		sum := sha256.Sum256(der)
		return base64.RawURLEncoding.EncodeToString(sum[:]), nil

	default:
		return "", fmt.Errorf("failed to create key id: %T", signer)
	}
}

type KeyStore struct {
	privateKeyMap map[string]crypto.Signer
	publicKeyMap  map[string]crypto.PublicKey
}

func NewKeyStore() *KeyStore {
	return &KeyStore{
		privateKeyMap: make(map[string]crypto.Signer),
		publicKeyMap:  make(map[string]crypto.PublicKey),
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
		err = store.AddPem(data)
		if err != nil {
			return err
		}
		return nil
	})
	return store, err
}

func (s *KeyStore) AddSigner(signer crypto.Signer) error {
	keyId, err := CreateKeyIdFromSigner(signer)
	if err != nil {
		return err
	}
	s.privateKeyMap[keyId] = signer
	s.publicKeyMap[keyId] = signer.Public()
	return nil
}

func (s *KeyStore) AddPublicKey(publicKey crypto.PublicKey) error {
	keyId, err := CreateKeyIdFromPublicKey(publicKey)
	if err != nil {
		return err
	}
	s.publicKeyMap[keyId] = publicKey
	return nil
}

func (s *KeyStore) AddPem(pemBytes []byte) error {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return errors.New("failed to decode PEM")
	}
	switch block.Type {
	case "PRIVATE KEY":
		signer, err := ParsePrivateKeyPem(pemBytes)
		if err != nil {
			return err
		}
		s.AddSigner(signer)
		return nil

	case "PUBLIC KEY":
		signer, err := ParsePublicKeyPem(pemBytes)
		if err != nil {
			return err
		}
		s.AddPublicKey(signer)
		return nil
	}
	return fmt.Errorf("PEM type is not PRIVATE KEY or PUBLIC KEY: %s", block.Type)
}

func (s *KeyStore) GetPrivateKey(keyId string) (crypto.Signer, bool) {
	entry, ok := s.privateKeyMap[keyId]
	if ok {
		return entry, true
	} else {
		return nil, false
	}
}

func (s *KeyStore) GetPublicKey(keyId string) (crypto.PublicKey, bool) {
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

func detectSignedMethod(key any) (jwt.SigningMethod, error) {
	switch key.(type) {
	case ed25519.PrivateKey, ed25519.PublicKey:
		return jwt.SigningMethodEdDSA, nil

	case *rsa.PrivateKey, *rsa.PublicKey:
		return jwt.SigningMethodRS256, nil

	default:
		return nil, fmt.Errorf("cannot detect algo for %T", key)
	}
}

func CreateJwt(
	signer crypto.Signer,
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

	alg, err := detectSignedMethod(signer)
	if err != nil {
		return "", err
	}
	token := jwt.NewWithClaims(alg, claims)
	kid, err := CreateKeyIdFromSigner(signer)
	if err != nil {
		return "", err
	}
	token.Header["kid"] = kid

	signed, err := signedString(token, signer)
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
			kid, _ := token.Header["kid"].(string)
			pubKey, ok := store.GetPublicKey(kid)
			if !ok {
				return nil, fmt.Errorf("key for %s not found", kid)
			}
			alg, err := detectSignedMethod(pubKey)
			if err != nil {
				return "", err
			}
			if token.Method.Alg() != alg.Alg() {
				return nil, fmt.Errorf("unexpected alg %s", token.Method.Alg())
			}
			return pubKey, nil
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
