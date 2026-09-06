package utils

import (
	"crypto/md5"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"github.com/OmniTrustILM/hashicorp-vault-connector/internal/logger"
	"strings"

	"github.com/google/uuid"
)

var log = logger.Get()

func GenerateRandomUUID() string {
	uuid, err := uuid.NewRandom()
	if err != nil {
		log.Error(err.Error())
	}
	return uuid.String()
}

func DeterministicGUID(parts ...string) string {
	combined := strings.Join(parts, "")

	md5hash := md5.New()
	md5hash.Write([]byte(combined))

	// convert the hash value to a string
	md5string := hex.EncodeToString(md5hash.Sum(nil))

	// generate the UUID from the
	// first 16 bytes of the MD5 hash
	uuidByte, err := uuid.FromBytes([]byte(md5string[0:16]))
	if err != nil {
		log.Error(err.Error())
	}

	return uuidByte.String()
}

func ExtractCommonName(csr []byte) (string, error) {

	csrParsed, err := x509.ParseCertificateRequest(csr)
	if err != nil {
		log.Error("Failed to parse CSR: " + err.Error())
		return "", fmt.Errorf("failed to parse CSR: %w", err)
	}

	commonName := csrParsed.Subject.CommonName
	return commonName, nil
}

func ExtractSerialNumber(certificate []byte) (string, error) {
	certificateParsed, err := x509.ParseCertificate(certificate)
	if err != nil {
		log.Error("Failed to parse certificate: " + err.Error())
		return "", fmt.Errorf("failed to parse certificate: %w", err)
	}

	bytes := certificateParsed.SerialNumber.Bytes()

	hexStr := make([]string, len(bytes))
	for i, b := range bytes {
		hexStr[i] = fmt.Sprintf("%02X", b)
	}
	return strings.ToLower(strings.Join(hexStr, ":")), nil
}

func GetCertificatesFromDer(pemData []byte) ([]string, error) {

	var certs []string
	for {
		block, rest := pem.Decode(pemData)
		if block == nil {
			break
		}

		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("failed to decode PEM block containing certificate")
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate: %w", err)
		}
		certBlock := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})

		certs = append(certs, string(certBlock))
		pemData = rest
	}

	return certs, nil
}
