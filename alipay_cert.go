package authhub

import (
	"crypto/md5"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"strconv"
	"strings"
)

// alipayCredentials holds the credential configuration for Alipay,
// supporting both public key mode and certificate mode.
type alipayCredentials struct {
	// alipayPublicKey is the Alipay public key for normal (non-cert) mode.
	alipayPublicKey *rsa.PublicKey

	// appCertSN is the application certificate serial number (cert mode).
	appCertSN string

	// alipayRootCertSN is the Alipay root certificate serial number (cert mode).
	alipayRootCertSN string

	// certPublicKeys maps certificate SN to its RSA public key.
	// This supports certificate rotation in cert mode.
	certPublicKeys map[string]*rsa.PublicKey

	// isCertMode indicates whether certificate mode is active.
	isCertMode bool
}

// calculateCertSN calculates the certificate serial number used by Alipay.
// It computes MD5(issuerDN + serialNumber) where issuerDN is the issuer's
// distinguished name string and serialNumber is the lowercase hexadecimal representation
// of the certificate's serial number.
func calculateCertSN(certContent string) (string, error) {
	block, _ := pem.Decode([]byte(certContent))
	if block == nil {
		return "", newAuthError(ErrKindInvalidConfig, "alipay", "", "failed to decode certificate PEM block", nil)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", newAuthError(ErrKindInvalidConfig, "alipay", "", "failed to parse certificate: "+err.Error(), err)
	}

	// Build the string: issuerDN + serialNumber (hex)
	issuerDN := cert.Issuer.String()
	serialNumber := cert.SerialNumber.Text(16)

	data := issuerDN + serialNumber
	hash := md5.Sum([]byte(data))
	return hex.EncodeToString(hash[:]), nil
}

// calculateRootCertSN calculates the combined serial number for an Alipay
// root certificate file that may contain multiple PEM blocks. Only
// certificates using SHA256WithRSA or SHA1WithRSA signature algorithms
// are included. The resulting SNs are joined with "_".
func calculateRootCertSN(rootCertContent string) (string, error) {
	var sns []string
	rest := []byte(rootCertContent)
	pemBlocks := 0
	parseSuccess := 0
	filteredCount := 0
	parseErrors := 0

	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		pemBlocks++

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			parseErrors++
			continue
		}
		parseSuccess++

		// Only include SHA256WithRSA and SHA1WithRSA
		if cert.SignatureAlgorithm != x509.SHA256WithRSA && cert.SignatureAlgorithm != x509.SHA1WithRSA {
			filteredCount++
			continue
		}

		issuerDN := cert.Issuer.String()
		serialNumber := cert.SerialNumber.Text(16)

		data := issuerDN + serialNumber
		hash := md5.Sum([]byte(data))
		sns = append(sns, hex.EncodeToString(hash[:]))
	}

	if pemBlocks > 0 && len(sns) == 0 {
		return "", newAuthError(
			ErrKindInvalidConfig,
			"alipay",
			"",
			"root certificate has no usable cert: pemBlocks="+strconv.Itoa(pemBlocks)+", parsed="+strconv.Itoa(parseSuccess)+", filtered="+strconv.Itoa(filteredCount)+", parseErrors="+strconv.Itoa(parseErrors),
			nil,
		)
	}

	return strings.Join(sns, "_"), nil
}

// extractPublicKeyFromCert extracts the RSA public key from a PEM-encoded
// X.509 certificate.
func extractPublicKeyFromCert(certContent string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(certContent))
	if block == nil {
		return nil, newAuthError(ErrKindInvalidConfig, "alipay", "", "failed to decode certificate PEM block", nil)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, newAuthError(ErrKindInvalidConfig, "alipay", "", "failed to parse certificate: "+err.Error(), err)
	}

	rsaKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, newAuthError(ErrKindInvalidConfig, "alipay", "", "certificate public key is not RSA", nil)
	}

	return rsaKey, nil
}
