package authhub

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"
)

// testGenerateSelfSignedCert generates a self-signed certificate and returns
// the PEM-encoded certificate string and the private key used to sign it.
func testGenerateSelfSignedCert(t *testing.T, key *rsa.PrivateKey, subject pkix.Name, sigAlgo x509.SignatureAlgorithm) string {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(123456789),
		Subject:               subject,
		Issuer:                subject,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SignatureAlgorithm:    sigAlgo,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	block := &pem.Block{Type: "CERTIFICATE", Bytes: certDER}
	return string(pem.EncodeToMemory(block))
}

// testGenerateSelfSignedCertWithSerial is like testGenerateSelfSignedCert but allows custom serial number.
func testGenerateSelfSignedCertWithSerial(t *testing.T, key *rsa.PrivateKey, subject pkix.Name, serial *big.Int, sigAlgo x509.SignatureAlgorithm) string {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               subject,
		Issuer:                subject,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SignatureAlgorithm:    sigAlgo,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	block := &pem.Block{Type: "CERTIFICATE", Bytes: certDER}
	return string(pem.EncodeToMemory(block))
}

// --- calculateCertSN ---

func TestCalculateCertSN_Valid(t *testing.T) {
	key := testGenerateRSAKey(t)
	subject := pkix.Name{
		CommonName:   "Test CA",
		Organization: []string{"Test Org"},
		Country:      []string{"CN"},
	}
	certPEM := testGenerateSelfSignedCert(t, key, subject, x509.SHA256WithRSA)

	sn, err := calculateCertSN(certPEM)
	if err != nil {
		t.Fatalf("calculateCertSN: unexpected error: %v", err)
	}
	if sn == "" {
		t.Fatal("calculateCertSN: returned empty SN")
	}
	// SN should be a 32-character hex string (MD5 hash)
	if len(sn) != 32 {
		t.Errorf("calculateCertSN: SN length = %d; want 32", len(sn))
	}
	// Should be lowercase hex
	for _, c := range sn {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			t.Errorf("calculateCertSN: SN contains non-hex char %q", c)
			break
		}
	}
}

func TestCalculateCertSN_Deterministic(t *testing.T) {
	key := testGenerateRSAKey(t)
	subject := pkix.Name{
		CommonName:   "Deterministic CA",
		Organization: []string{"Test Org"},
		Country:      []string{"CN"},
	}
	certPEM := testGenerateSelfSignedCert(t, key, subject, x509.SHA256WithRSA)

	sn1, err := calculateCertSN(certPEM)
	if err != nil {
		t.Fatalf("calculateCertSN (1): %v", err)
	}
	sn2, err := calculateCertSN(certPEM)
	if err != nil {
		t.Fatalf("calculateCertSN (2): %v", err)
	}
	if sn1 != sn2 {
		t.Errorf("calculateCertSN: not deterministic: %q != %q", sn1, sn2)
	}
}

func TestCalculateCertSN_DifferentCerts(t *testing.T) {
	key1 := testGenerateRSAKey(t)
	key2 := testGenerateRSAKey(t)
	subject := pkix.Name{
		CommonName:   "Test CA",
		Organization: []string{"Test Org"},
		Country:      []string{"CN"},
	}
	cert1 := testGenerateSelfSignedCertWithSerial(t, key1, subject, big.NewInt(111), x509.SHA256WithRSA)
	cert2 := testGenerateSelfSignedCertWithSerial(t, key2, subject, big.NewInt(222), x509.SHA256WithRSA)

	sn1, err := calculateCertSN(cert1)
	if err != nil {
		t.Fatalf("calculateCertSN(cert1): %v", err)
	}
	sn2, err := calculateCertSN(cert2)
	if err != nil {
		t.Fatalf("calculateCertSN(cert2): %v", err)
	}
	if sn1 == sn2 {
		t.Error("calculateCertSN: different certs should have different SNs")
	}
}

func TestCalculateCertSN_UsesHexSerialNumber(t *testing.T) {
	key := testGenerateRSAKey(t)
	subject := pkix.Name{
		CommonName:   "Hex Serial CA",
		Organization: []string{"Test Org"},
		Country:      []string{"CN"},
	}
	certPEM := testGenerateSelfSignedCertWithSerial(t, key, subject, big.NewInt(255), x509.SHA256WithRSA)

	sn, err := calculateCertSN(certPEM)
	if err != nil {
		t.Fatalf("calculateCertSN(hex serial): %v", err)
	}

	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		t.Fatal("decode cert pem: nil block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}

	hexInput := cert.Issuer.String() + cert.SerialNumber.Text(16)
	hexDigest := md5.Sum([]byte(hexInput))
	wantHex := hex.EncodeToString(hexDigest[:])
	if sn != wantHex {
		t.Errorf("SN = %q; want hex-based %q", sn, wantHex)
	}

	decInput := cert.Issuer.String() + cert.SerialNumber.String()
	decDigest := md5.Sum([]byte(decInput))
	decSN := hex.EncodeToString(decDigest[:])
	if sn == decSN {
		t.Errorf("SN unexpectedly equals decimal-based value %q", decSN)
	}
}

func TestCalculateCertSN_InvalidPEM(t *testing.T) {
	_, err := calculateCertSN("not-a-valid-pem")
	if err == nil {
		t.Fatal("calculateCertSN(invalid): expected error, got nil")
	}
	var authErr *AuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("calculateCertSN(invalid): error is not AuthError: %T", err)
	}
	if authErr.Kind != ErrKindInvalidConfig {
		t.Errorf("calculateCertSN(invalid): Kind = %q; want %q", authErr.Kind, ErrKindInvalidConfig)
	}
}

func TestCalculateCertSN_EmptyInput(t *testing.T) {
	_, err := calculateCertSN("")
	if err == nil {
		t.Fatal("calculateCertSN(empty): expected error, got nil")
	}
	if !errors.Is(err, ErrInvalidConfig) {
		t.Error("calculateCertSN(empty): errors.Is(err, ErrInvalidConfig) = false")
	}
}

func TestCalculateCertSN_InvalidCertData(t *testing.T) {
	// Valid PEM block but invalid certificate data
	invalidPEM := "-----BEGIN CERTIFICATE-----\nbm90LWEtdmFsaWQtY2VydA==\n-----END CERTIFICATE-----"
	_, err := calculateCertSN(invalidPEM)
	if err == nil {
		t.Fatal("calculateCertSN(invalid cert): expected error, got nil")
	}
	if !errors.Is(err, ErrInvalidConfig) {
		t.Error("calculateCertSN(invalid cert): errors.Is(err, ErrInvalidConfig) = false")
	}
}

// --- calculateRootCertSN ---

func TestCalculateRootCertSN_SingleCert(t *testing.T) {
	key := testGenerateRSAKey(t)
	subject := pkix.Name{
		CommonName:   "Root CA",
		Organization: []string{"Root Org"},
		Country:      []string{"CN"},
	}
	certPEM := testGenerateSelfSignedCert(t, key, subject, x509.SHA256WithRSA)

	sn, err := calculateRootCertSN(certPEM)
	if err != nil {
		t.Fatalf("calculateRootCertSN(single): unexpected error: %v", err)
	}
	if sn == "" {
		t.Fatal("calculateRootCertSN(single): returned empty SN")
	}
	// Should not contain underscore for single cert
	if strings.Contains(sn, "_") {
		t.Errorf("calculateRootCertSN(single): SN should not contain underscore: %q", sn)
	}
}

func TestCalculateRootCertSN_MultipleCerts(t *testing.T) {
	key1 := testGenerateRSAKey(t)
	key2 := testGenerateRSAKey(t)
	subject1 := pkix.Name{
		CommonName:   "Root CA 1",
		Organization: []string{"Root Org 1"},
		Country:      []string{"CN"},
	}
	subject2 := pkix.Name{
		CommonName:   "Root CA 2",
		Organization: []string{"Root Org 2"},
		Country:      []string{"CN"},
	}
	cert1PEM := testGenerateSelfSignedCertWithSerial(t, key1, subject1, big.NewInt(111), x509.SHA256WithRSA)
	cert2PEM := testGenerateSelfSignedCertWithSerial(t, key2, subject2, big.NewInt(222), x509.SHA1WithRSA)

	combinedPEM := cert1PEM + cert2PEM

	sn, err := calculateRootCertSN(combinedPEM)
	if err != nil {
		t.Fatalf("calculateRootCertSN(multi): unexpected error: %v", err)
	}
	// Should contain underscore separator
	parts := strings.Split(sn, "_")
	if len(parts) != 2 {
		t.Fatalf("calculateRootCertSN(multi): expected 2 parts, got %d: %q", len(parts), sn)
	}
	for i, part := range parts {
		if len(part) != 32 {
			t.Errorf("calculateRootCertSN(multi): part[%d] length = %d; want 32", i, len(part))
		}
	}
}

func TestCalculateRootCertSN_FiltersUnsupportedAlgorithms(t *testing.T) {
	key := testGenerateRSAKey(t)
	subjectSHA256 := pkix.Name{
		CommonName:   "SHA256 Root",
		Organization: []string{"SHA256 Org"},
		Country:      []string{"CN"},
	}
	subjectSHA384 := pkix.Name{
		CommonName:   "SHA384 Root",
		Organization: []string{"SHA384 Org"},
		Country:      []string{"CN"},
	}

	sha256PEM := testGenerateSelfSignedCertWithSerial(t, key, subjectSHA256, big.NewInt(111), x509.SHA256WithRSA)
	sha384PEM := testGenerateSelfSignedCertWithSerial(t, key, subjectSHA384, big.NewInt(222), x509.SHA384WithRSA)

	combinedPEM := sha256PEM + sha384PEM

	sn, err := calculateRootCertSN(combinedPEM)
	if err != nil {
		t.Fatalf("calculateRootCertSN(filter): unexpected error: %v", err)
	}
	// Should only contain the SHA256 cert SN (SHA384 filtered out)
	if strings.Contains(sn, "_") {
		t.Errorf("calculateRootCertSN(filter): SHA384 cert should be filtered out: %q", sn)
	}
	if len(sn) != 32 {
		t.Errorf("calculateRootCertSN(filter): SN length = %d; want 32", len(sn))
	}
}

func TestCalculateRootCertSN_SHA1WithRSA(t *testing.T) {
	key := testGenerateRSAKey(t)
	subject := pkix.Name{
		CommonName:   "SHA1 Root",
		Organization: []string{"SHA1 Org"},
		Country:      []string{"CN"},
	}
	certPEM := testGenerateSelfSignedCert(t, key, subject, x509.SHA1WithRSA)

	sn, err := calculateRootCertSN(certPEM)
	if err != nil {
		t.Fatalf("calculateRootCertSN(SHA1): unexpected error: %v", err)
	}
	if sn == "" {
		t.Fatal("calculateRootCertSN(SHA1): returned empty SN")
	}
	if len(sn) != 32 {
		t.Errorf("calculateRootCertSN(SHA1): SN length = %d; want 32", len(sn))
	}
}

func TestCalculateRootCertSN_UsesHexSerialNumber(t *testing.T) {
	key := testGenerateRSAKey(t)
	subject := pkix.Name{
		CommonName:   "Hex Root",
		Organization: []string{"Root Org"},
		Country:      []string{"CN"},
	}
	certPEM := testGenerateSelfSignedCertWithSerial(t, key, subject, big.NewInt(255), x509.SHA256WithRSA)

	sn, err := calculateRootCertSN(certPEM)
	if err != nil {
		t.Fatalf("calculateRootCertSN(hex serial): %v", err)
	}

	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		t.Fatal("decode cert pem: nil block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}

	hexInput := cert.Issuer.String() + cert.SerialNumber.Text(16)
	hexDigest := md5.Sum([]byte(hexInput))
	wantHex := hex.EncodeToString(hexDigest[:])
	if sn != wantHex {
		t.Errorf("root SN = %q; want hex-based %q", sn, wantHex)
	}
}

func TestCalculateRootCertSN_AllFiltered(t *testing.T) {
	key := testGenerateRSAKey(t)
	subject := pkix.Name{
		CommonName:   "SHA384 Root",
		Organization: []string{"SHA384 Org"},
		Country:      []string{"CN"},
	}
	certPEM := testGenerateSelfSignedCertWithSerial(t, key, subject, big.NewInt(111), x509.SHA384WithRSA)

	_, err := calculateRootCertSN(certPEM)
	if err == nil {
		t.Fatal("calculateRootCertSN(allFiltered): expected error, got nil")
	}
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("calculateRootCertSN(allFiltered): errors.Is(err, ErrInvalidConfig) = false")
	}
}

func TestCalculateRootCertSN_UnparseableCertificateBlock(t *testing.T) {
	invalidCertBlock := "-----BEGIN CERTIFICATE-----\nbm90LWEtdmFsaWQtY2VydA==\n-----END CERTIFICATE-----"

	_, err := calculateRootCertSN(invalidCertBlock)
	if err == nil {
		t.Fatal("calculateRootCertSN(unparseable): expected error, got nil")
	}
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("calculateRootCertSN(unparseable): errors.Is(err, ErrInvalidConfig) = false")
	}
}

func TestCalculateRootCertSN_InvalidPEM(t *testing.T) {
	_, err := calculateRootCertSN("not-a-valid-pem")
	if err != nil {
		t.Fatalf("calculateRootCertSN(invalid): should not error for no PEM blocks, got: %v", err)
	}
}

func TestCalculateRootCertSN_EmptyInput(t *testing.T) {
	sn, err := calculateRootCertSN("")
	if err != nil {
		t.Fatalf("calculateRootCertSN(empty): unexpected error: %v", err)
	}
	if sn != "" {
		t.Errorf("calculateRootCertSN(empty): expected empty, got %q", sn)
	}
}

// --- extractPublicKeyFromCert ---

func TestExtractPublicKeyFromCert_Valid(t *testing.T) {
	key := testGenerateRSAKey(t)
	subject := pkix.Name{
		CommonName:   "Test Cert",
		Organization: []string{"Test Org"},
		Country:      []string{"CN"},
	}
	certPEM := testGenerateSelfSignedCert(t, key, subject, x509.SHA256WithRSA)

	pubKey, err := extractPublicKeyFromCert(certPEM)
	if err != nil {
		t.Fatalf("extractPublicKeyFromCert: unexpected error: %v", err)
	}
	if pubKey.N.Cmp(key.N) != 0 || pubKey.E != key.E {
		t.Error("extractPublicKeyFromCert: extracted key does not match original")
	}
}

func TestExtractPublicKeyFromCert_InvalidPEM(t *testing.T) {
	_, err := extractPublicKeyFromCert("not-a-valid-pem")
	if err == nil {
		t.Fatal("extractPublicKeyFromCert(invalid): expected error, got nil")
	}
	var authErr *AuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("extractPublicKeyFromCert(invalid): error is not AuthError: %T", err)
	}
	if authErr.Kind != ErrKindInvalidConfig {
		t.Errorf("extractPublicKeyFromCert(invalid): Kind = %q; want %q", authErr.Kind, ErrKindInvalidConfig)
	}
}

func TestExtractPublicKeyFromCert_EmptyInput(t *testing.T) {
	_, err := extractPublicKeyFromCert("")
	if err == nil {
		t.Fatal("extractPublicKeyFromCert(empty): expected error, got nil")
	}
	if !errors.Is(err, ErrInvalidConfig) {
		t.Error("extractPublicKeyFromCert(empty): errors.Is(err, ErrInvalidConfig) = false")
	}
}

func TestExtractPublicKeyFromCert_InvalidCertData(t *testing.T) {
	invalidPEM := "-----BEGIN CERTIFICATE-----\nbm90LWEtdmFsaWQtY2VydA==\n-----END CERTIFICATE-----"
	_, err := extractPublicKeyFromCert(invalidPEM)
	if err == nil {
		t.Fatal("extractPublicKeyFromCert(invalid cert): expected error, got nil")
	}
	if !errors.Is(err, ErrInvalidConfig) {
		t.Error("extractPublicKeyFromCert(invalid cert): errors.Is(err, ErrInvalidConfig) = false")
	}
}

// --- alipayCredentials ---

func TestAlipayCredentials_PublicKeyMode(t *testing.T) {
	key := testGenerateRSAKey(t)
	creds := &alipayCredentials{
		alipayPublicKey: &key.PublicKey,
		isCertMode:      false,
	}
	if creds.isCertMode {
		t.Error("expected isCertMode = false")
	}
	if creds.alipayPublicKey == nil {
		t.Error("expected alipayPublicKey to be set")
	}
}

func TestAlipayCredentials_CertMode(t *testing.T) {
	key := testGenerateRSAKey(t)
	creds := &alipayCredentials{
		appCertSN:        "abc123",
		alipayRootCertSN: "def456",
		certPublicKeys:   map[string]*rsa.PublicKey{"abc123": &key.PublicKey},
		isCertMode:       true,
	}
	if !creds.isCertMode {
		t.Error("expected isCertMode = true")
	}
	if creds.appCertSN != "abc123" {
		t.Errorf("appCertSN = %q; want %q", creds.appCertSN, "abc123")
	}
	if creds.alipayRootCertSN != "def456" {
		t.Errorf("alipayRootCertSN = %q; want %q", creds.alipayRootCertSN, "def456")
	}
	if _, ok := creds.certPublicKeys["abc123"]; !ok {
		t.Error("expected certPublicKeys to contain 'abc123'")
	}
}

// --- calculateCertSN consistency with calculateRootCertSN ---

func TestCertSN_ConsistencyBetweenFunctions(t *testing.T) {
	key := testGenerateRSAKey(t)
	subject := pkix.Name{
		CommonName:   "Consistent Root",
		Organization: []string{"Test Org"},
		Country:      []string{"CN"},
	}
	certPEM := testGenerateSelfSignedCert(t, key, subject, x509.SHA256WithRSA)

	certSN, err := calculateCertSN(certPEM)
	if err != nil {
		t.Fatalf("calculateCertSN: %v", err)
	}

	rootSN, err := calculateRootCertSN(certPEM)
	if err != nil {
		t.Fatalf("calculateRootCertSN: %v", err)
	}

	// For a single SHA256WithRSA cert, both should produce the same SN
	if certSN != rootSN {
		t.Errorf("inconsistent SNs: calculateCertSN=%q, calculateRootCertSN=%q", certSN, rootSN)
	}
}
