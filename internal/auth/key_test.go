package auth

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func mustSuccess(t *testing.T, e error, format string, args ...any) {
	t.Helper()
	if e != nil {
		if format == "" {
			format = "Must success, but failed"
		}
		if len(args) == 0 {
			t.Fatalf("%s: %v", format, e)
		} else {
			t.Fatalf(format, args...)
		}
	}
}

func mustOk(t *testing.T, ok bool, format string, args ...any) {
	t.Helper()
	if !ok {
		if format == "" {
			format = "Must ok, but failed"
		}
		if len(args) == 0 {
			t.Fatalf("%s", format)
		} else {
			t.Fatalf(format, args...)
		}
	}
}

func mustError(t *testing.T, e error, format string, args ...any) {
	t.Helper()
	if e == nil {
		if format == "" {
			format = "Must error, but succeed"
		}
		if len(args) == 0 {
			t.Fatalf("%s: %v", format, e)
		} else {
			t.Fatalf(format, args...)
		}
	}
}

func createKeyIdFromPublicKeyOrPanic(pub crypto.PublicKey) string {
	keyid, err := CreateKeyIdFromPublicKey(pub)
	if err != nil {
		panic("CreateKeyIdFromPublicKey()")
	}
	return keyid
}

func createKeyIdFromSignerOrPanic(signer crypto.Signer) string {
	keyid, err := CreateKeyIdFromSigner(signer)
	if err != nil {
		panic("CreateKeyIdFromSigner()")
	}
	return keyid
}

type testKeyPair struct {
	publicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey
	publicPem  []byte
	privatePem []byte
}

func makeKeyPair(t *testing.T) testKeyPair {
	pubKey, priKey, err := GenerateKeyPair()
	mustSuccess(t, err, "GenerateKeyPair()")

	pubPem, err := PublicKeyToPem(pubKey)
	mustSuccess(t, err, "PublicKeyToPem()")

	recoveredPubKey, err := ParsePublicKeyPem(pubPem)
	mustSuccess(t, err, "ParsePublicKeyPem()")

	if !bytes.Equal(pubKey, recoveredPubKey.(ed25519.PublicKey)) {
		t.Error("PublicKey PEM convertion failed.")
	}

	priPem, err := PrivateKeyToPem(priKey)
	mustSuccess(t, err, "PrivateKeyToPem()")

	recoveredPriKey, err := ParsePrivateKeyPem(priPem)
	mustSuccess(t, err, "ParsePrivateKeyPem()")

	if !bytes.Equal(priKey, recoveredPriKey.(ed25519.PrivateKey)) {
		t.Error("PrivateKey PEM convertion failed.")
	}

	return testKeyPair{
		publicKey:  pubKey,
		privateKey: priKey,
		publicPem:  pubPem,
		privatePem: priPem,
	}
}

func makeKeyPairs(t *testing.T, nrPairs int) (keyPairs []testKeyPair, store *KeyStore) {
	keyPairs = make([]testKeyPair, nrPairs)
	store = NewKeyStore()

	for i := 0; i < nrPairs; i++ {
		keyPairs[i] = makeKeyPair(t)
		store.AddSigner(keyPairs[i].privateKey)
	}

	return keyPairs, store
}

type errorReader struct{}

func (errorReader) Read(p []byte) (int, error) {
	return 0, fmt.Errorf("fot test")
}

func expectPanic(t *testing.T) {
	if r := recover(); r == nil {
		t.Fatalf("expected panic, but did not panic")
	}
}

func Test_GenerateKeyPair(t *testing.T) {
	pubKey, priKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if len(pubKey) == 0 || len(priKey) == 0 {
		t.Error("Key is empty.")
	}
	GenerateKeyPair()
}

func Test_generateKeyPair(t *testing.T) {
	randReader = errorReader{}
	GenerateKeyPair()
	randReader = rand.Reader
}

func Test_CreateJwt(t *testing.T) {
	p := makeKeyPair(t)

	jwtStr, err := CreateJwt(
		p.privateKey, "My ID Service", []string{"your app"}, "user@example.jp",
		CreateJwtAppParam{
			UserId: "user001",
		},
	)
	mustSuccess(t, err, "")
	if len(jwtStr) == 0 {
		t.Error("JWT is empty.")
	}

	// エラーケース
	signedString = func(_ *jwt.Token, _ any) (string, error) {
		return "", errors.New("boom")
	}
	jwtStr, err = CreateJwt(
		p.privateKey, "My ID Service", []string{"your app"}, "user@example.jp",
		CreateJwtAppParam{
			UserId: "user001",
		},
	)
	mustError(t, err, "")
	signedString = (*jwt.Token).SignedString

	// 非対応のアルゴリズム
	jwtStr, err = CreateJwt(
		&TestSigner{}, "svc", []string{"app"}, "user@example.jp",
		CreateJwtAppParam{UserId: "user001"},
	)
	mustError(t, err, "")
	if !strings.Contains(err.Error(), "cannot detect") {
		t.Errorf("invalid error message: %v", err)
	}
}

func Test_VerifyJwt(t *testing.T) {
	pp, _ := makeKeyPairs(t, 1)
	p := pp[0]
	store := NewKeyStore()
	store.AddPublicKey(p.publicKey)

	issuer := "My ID Service"
	audiences := []string{"app1", "app2"}
	subject := "user@example.jp"
	jwtStr, err := CreateJwt(
		p.privateKey, issuer, audiences, subject,
		CreateJwtAppParam{UserId: "user001"},
	)
	mustSuccess(t, err, "")

	claims, err := VerifyJwt(store, jwtStr, issuer, audiences[0])
	mustSuccess(t, err, "")
	if claims.UserId != "user001" {
		t.Errorf("Invalid UserId: %s", claims.UserId)
	}

	// 無効なIssuerテスト
	claims, err = VerifyJwt(store, jwtStr, "Invalid Issuer", audiences[0])
	mustError(t, err, "")

	// 無効なAudienceテスト
	claims, err = VerifyJwt(store, jwtStr, issuer, "invalid")
	mustError(t, err, "")

	// 鍵が無い場合のテスト
	claims, err = VerifyJwt(NewKeyStore(), jwtStr, issuer, audiences[0])
	mustError(t, err, "")

	// Exp必須テスト
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA,
		&AppClaims{
			UserId: "user001",
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    issuer,
				Subject:   subject,
				Audience:  audiences,
				IssuedAt:  jwt.NewNumericDate(time.Now()),
				NotBefore: jwt.NewNumericDate(time.Now()),
			},
		})
	token.Header["kid"] = createKeyIdFromSignerOrPanic(p.privateKey)
	jwtStr, err = token.SignedString(p.privateKey)
	mustSuccess(t, err, "")
	_, err = VerifyJwt(store, jwtStr, issuer, audiences[0])
	mustError(t, err, "")
	if !errors.Is(err, jwt.ErrTokenRequiredClaimMissing) ||
		!strings.Contains(err.Error(), " exp ") {
		t.Errorf("ErrTokenRequiredClaimMissing expected: %v", err)
	}

	// 無効な署名アルゴリズム
	token = jwt.NewWithClaims(jwt.SigningMethodHS256,
		&AppClaims{
			UserId: "user001",
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    issuer,
				Subject:   subject,
				Audience:  audiences,
				IssuedAt:  jwt.NewNumericDate(time.Now()),
				NotBefore: jwt.NewNumericDate(time.Now()),
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
			},
		})
	token.Header["kid"] = createKeyIdFromSignerOrPanic(p.privateKey)
	jwtStr, err = token.SignedString([]byte("secret"))
	mustSuccess(t, err, "")
	_, err = VerifyJwt(store, jwtStr, issuer, audiences[0])
	mustError(t, err, "")
	if !strings.Contains(err.Error(), "unexpected alg") {
		t.Errorf("ErrTokenRequiredClaimMissing expected: %v", err)
	}

	// 非対応の署名アルゴリズム
	token.Header["kid"] = "test"
	store.publicKeyMap["test"] = "dummy"
	jwtStr, err = token.SignedString([]byte("secret"))
	_, err = VerifyJwt(store, jwtStr, issuer, audiences[0])
	mustError(t, err, "")
	if !strings.Contains(err.Error(), "cannot detect") {
		t.Errorf("invalid error message: %v", err)
	}
}

type TestSigner struct{}

func (*TestSigner) Public() crypto.PublicKey {
	panic("dummy")
}

func (*TestSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	panic("dummy")
}

func ReadConfig(fsys fs.FS) (string, error) {
	b, err := fs.ReadFile(fsys, "config.json")
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func Test_KeyId(t *testing.T) {
	p := makeKeyPair(t)

	a := createKeyIdFromPublicKeyOrPanic(p.publicKey)
	b := createKeyIdFromSignerOrPanic(p.privateKey)
	if a != b {
		t.Errorf("KeyId different: %s != %s", a, b)
	}
}

func Test_NewKeyStoreFromFS(t *testing.T) {
	p1 := makeKeyPair(t)
	p2 := makeKeyPair(t)
	p3 := makeKeyPair(t)

	fsys := fstest.MapFS{
		"pri1.pem": &fstest.MapFile{
			Data: []byte(p1.privatePem),
		},
		"pri2.pem": &fstest.MapFile{
			Data: []byte(p2.privatePem),
		},
		"pub3.pem": &fstest.MapFile{
			Data: []byte(p3.publicPem),
		},
	}

	store, err := NewKeyStoreFromFS(fsys)
	mustSuccess(t, err, "NewKeyStore() failed.")

	if store.Len() != 2 {
		t.Errorf("Loaded files not 2.")
	}

	got, ok := store.GetPrivateKey(createKeyIdFromSignerOrPanic(p1.privateKey))
	mustOk(t, ok, "Failed to get loaded private key.")
	priKey, ok := got.(ed25519.PrivateKey)
	mustOk(t, ok, "Failed to get loaded private key.")
	if !bytes.Equal(priKey, p1.privateKey) {
		t.Errorf("Failed to get loaded private key. %v != %v", p1.privateKey, got)
	}

	_, ok = store.GetPrivateKey("invalid")
	if ok {
		t.Error("Get() must fail.")
	}
}

type FSFunc func(name string) (fs.File, error)

func (f FSFunc) Open(name string) (fs.File, error) {
	return f(name)
}

func Test_NewKeyStoreFromFS_ForCoverage(t *testing.T) {
	// test 1
	fsys := FSFunc(func(name string) (fs.File, error) {
		return nil, errors.New("boom")
	})
	_, err := NewKeyStoreFromFS(fsys)
	mustError(t, err, "Must fail.")

	// test 2
	base := fstest.MapFS{
		"pri1.pem": &fstest.MapFile{Data: []byte("dummy")},
	}
	fsys = FSFunc(func(name string) (fs.File, error) {
		if name == "pri1.pem" {
			return nil, errors.New("boom")
		}
		return base.Open(name)
	})
	_, err = NewKeyStoreFromFS(fsys)
	mustError(t, err, "Must fail.")

	// test 3
	mapfs := fstest.MapFS{
		"pri1.pem": &fstest.MapFile{Data: []byte("dummy")},
	}
	_, err = NewKeyStoreFromFS(mapfs)
	mustError(t, err, "Must fail.")
}

func Test_PEM(t *testing.T) {
	p := makeKeyPair(t)

	recoveredPubKey, err := ParsePublicKeyPem(p.publicPem)
	mustSuccess(t, err, "ParsePublicKeyPem()")

	if !bytes.Equal(p.publicKey, recoveredPubKey.(ed25519.PublicKey)) {
		t.Error("PublicKey PEM convertion failed.")
	}

	recoveredPriKey, err := ParsePrivateKeyPem(p.privatePem)
	mustSuccess(t, err, "ParsePrivateKeyPem()")

	if !bytes.Equal(p.privateKey, recoveredPriKey.(ed25519.PrivateKey)) {
		t.Error("PrivateKey PEM convertion failed.")
	}

	// public key check ===================
	// for coverage
	v, err := PublicKeyToPem(nil)
	mustError(t, err, fmt.Sprintf("PublicKeyToPEM(nil) must return error: %v", v))

	// for coverage
	marshalPKIXPublicKey = func(any) ([]byte, error) { return nil, errors.New("boom") }
	v, err = PublicKeyToPem(p.publicKey)
	marshalPKIXPublicKey = x509.MarshalPKIXPublicKey
	mustError(t, err, fmt.Sprintf("PublicKeyToPem() must return error: %v", v))

	// for coverage
	recoveredPubKey, err = ParsePublicKeyPem(nil)
	mustError(t, err, "ParsePublicKeyPem(nil) must return error")

	// for coverage
	recoveredPubKey, err = ParsePublicKeyPem(p.privatePem)
	mustError(t, err, "ParsePublicKeyPem(p.privatePem) must return error")

	// for coverage
	parsePKIXPublicKey = func([]byte) (any, error) { return nil, errors.New("boom") }
	recoveredPubKey, err = ParsePublicKeyPem(p.publicPem)
	mustError(t, err, "ParsePublicKeyPem(p.publicPem)-1 must return error")
	parsePKIXPublicKey = x509.ParsePKIXPublicKey

	// for coverage
	parsePKIXPublicKey = func([]byte) (any, error) { return "", nil }
	recoveredPubKey, err = ParsePublicKeyPem(p.publicPem)
	mustError(t, err, "ParsePublicKeyPem(p.publicPem)-2 must return error")
	parsePKIXPublicKey = x509.ParsePKIXPublicKey

	// private key check ===================
	// for coverage
	v, err = PrivateKeyToPem(nil)
	mustError(t, err, fmt.Sprintf("PrivateKeyToPem(nil) must return error: %v", v))

	// for coverage
	marshalPKCS8PrivateKey = func(any) ([]byte, error) { return nil, errors.New("boom") }
	v, err = PrivateKeyToPem(p.privateKey)
	marshalPKCS8PrivateKey = x509.MarshalPKCS8PrivateKey
	mustError(t, err, fmt.Sprintf("PrivateKeyToPem() must return error: %v", v))

	// for coverage
	recoveredPriKey, err = ParsePrivateKeyPem(nil)
	mustError(t, err, "ParsePrivateKeyPem(nil) must return error")

	// for coverage
	recoveredPriKey, err = ParsePrivateKeyPem(p.publicPem)
	mustError(t, err, "ParsePrivateKeyPem(p.publicPem) must return error")

	// for coverage
	parsePKCS8PrivateKey = func([]byte) (any, error) { return nil, errors.New("boom") }
	recoveredPriKey, err = ParsePrivateKeyPem(p.privatePem)
	mustError(t, err, "ParsePrivateKeyPem(p.privatePem)-1 must return error")
	parsePKCS8PrivateKey = x509.ParsePKCS8PrivateKey

	// for coverage
	parsePKCS8PrivateKey = func([]byte) (any, error) { return "", nil }
	recoveredPriKey, err = ParsePrivateKeyPem(p.privatePem)
	mustError(t, err, "ParsePrivateKeyPem(p.privatePem)-2 must return error")
	parsePKCS8PrivateKey = x509.ParsePKCS8PrivateKey
}

func Test_RSA(t *testing.T) {
	// RSAも扱えることを確認する。（複数アルゴリズム対応確認）

	signer, err := GenerateRSAKeyPair()
	mustSuccess(t, err, "GenerateRSAKeyPair() failed")
	priPem, err := PrivateKeyToPem(signer)
	mustSuccess(t, err, "PrivateKeyToPem() failed")
	pubPem, err := PublicKeyToPem(signer.Public())
	mustSuccess(t, err, "PublicKeyToPem() failed")
	fsys := fstest.MapFS{
		"pri1.pem": &fstest.MapFile{Data: []byte(priPem)},
		"pub1.pem": &fstest.MapFile{Data: []byte(pubPem)},
	}

	store, err := NewKeyStoreFromFS(fsys)
	mustSuccess(t, err, "NewKeyStore() failed.")

	issuer := "My ID Service"
	audiences := []string{"app1", "app2"}
	subject := "user@example.jp"
	jwtStr, err := CreateJwt(
		signer, issuer, audiences, subject,
		CreateJwtAppParam{UserId: "user001"},
	)
	mustSuccess(t, err, "")

	claims, err := VerifyJwt(store, jwtStr, issuer, audiences[0])
	mustSuccess(t, err, "")
	if claims.UserId != "user001" {
		t.Errorf("Invalid UserId: %s", claims.UserId)
	}
}

func generateSigner(ty reflect.Type) (crypto.Signer, error) {
	switch ty {
	case reflect.TypeOf(ed25519.PrivateKey{}):
		_, priKey, err := GenerateKeyPair()
		if err != nil {
			return nil, err
		}
		return priKey, nil
	case reflect.TypeOf(&rsa.PrivateKey{}):
		return GenerateRSAKeyPair()
	default:
		return nil, fmt.Errorf("unsupported type: %T", ty)
	}
}

func Test_Supported_KeyTypes(t *testing.T) {
	for ty := range supportedPrivateKeyTypes {
		signer, err := generateSigner(ty)
		mustSuccess(t, err, "GenerateSigner(%v) failed.", ty)

		// PEM変換
		pem, err := PrivateKeyToPem(signer)
		mustSuccess(t, err, "PrivateKeyToPem(%v) failed.", ty)
		_, err = ParsePrivateKeyPem(pem)
		mustSuccess(t, err, "ParsePrivateKeyPem(%v) failed.", ty)

		// PEM読み込み
		pubKey := signer.Public()
		pem, err = PublicKeyToPem(pubKey)
		mustSuccess(t, err, "PublicKeyToPem(%v) failed.", ty)
		_, err = ParsePublicKeyPem(pem)
		mustSuccess(t, err, "ParsePublicKeyPem(%v) failed.", ty)

		// KeyId生成
		_, err = CreateKeyIdFromPublicKey(pubKey)
		mustSuccess(t, err, "CreateKeyIdFromPublicKey(%v) failed.", ty)
		_, err = CreateKeyIdFromSigner(signer)
		mustSuccess(t, err, "CreateKeyIdFromSigner(%v) failed.", ty)

		// detectSignedMethod
		_, err = detectSignedMethod(signer)
		mustSuccess(t, err, "detectSignedMethod(%v:signer) failed.", ty)
		_, err = detectSignedMethod(pubKey)
		mustSuccess(t, err, "detectSignedMethod(%v:pubKey) failed.", ty)
	}
}
