// Copyright (C) 2023-2024 Holger de Carne and contributors
//
// This software may be modified and distributed under the terms
// of the MIT license.  See the LICENSE file for details.

package certs

import (
	"archive/zip"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/tdrn-org/go-certstore/keys"
	"software.sslmate.com/src/go-pkcs12"
)

// ReadCertificates reads X.509 certificates from the given [io.Reader].
func ReadCertificates(in io.Reader) ([]*x509.Certificate, error) {
	bytes, err := io.ReadAll(in)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificates (cause: %w)", err)
	}
	decoded, err := decodeCertificates(bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to decode certificates (cause: %w)", err)
	}
	return decoded, nil
}

// ReadCertificatesFile reads X.509 certificates from the given file name.
func ReadCertificatesFile(filename string) ([]*x509.Certificate, error) {
	bytes, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificates from file '%s' (cause: %w)", filename, err)
	}
	decoded, err := decodeCertificates(bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to decode certificates from file '%s' (cause: %w)", filename, err)
	}
	return decoded, nil
}

func decodeCertificates(bytes []byte) ([]*x509.Certificate, error) {
	decoded := make([]*x509.Certificate, 0)
	block, rest := pem.Decode(bytes)
	for block != nil {
		certs, err := x509.ParseCertificates(block.Bytes)
		if err != nil {
			return decoded, err
		}
		decoded = append(decoded, certs...)
		block, rest = pem.Decode(rest)
	}
	if len(decoded) == 0 {
		certs, err := x509.ParseCertificates(bytes)
		if err != nil {
			return decoded, err
		}
		decoded = append(decoded, certs...)
	}
	return decoded, nil
}

// WriteCertificatesPEM writes X.509 certificates in PEM format to the given [io.Writer].
func WriteCertificatesPEM(out io.Writer, certificates []*x509.Certificate) error {
	encoded := encodeCertificatesPEM(certificates)
	_, err := out.Write(encoded)
	return err
}

// WriteCertificatesPEMFile writes X.509 certificates in PEM format to the given file name.
func WriteCertificatesPEMFile(filename string, certificates []*x509.Certificate, perm os.FileMode) error {
	encoded := encodeCertificatesPEM(certificates)
	return os.WriteFile(filename, encoded, perm)
}

func encodeCertificatesPEM(certificates []*x509.Certificate) []byte {
	encoded := make([]byte, 0)
	for _, certificate := range certificates {
		block := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certificate.Raw,
		}
		encoded = append(encoded, pem.EncodeToMemory(block)...)
	}
	return encoded
}

func encodeKeyPEM(key crypto.PrivateKey) ([]byte, error) {
	encodedKey, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		algorithm, _ := keys.AlgorithmFromKey(keys.KeyFromPrivate(key).Public())
		return nil, fmt.Errorf("failed to marshal private key of type '%s' (cause: %w)", algorithm, err)
	}
	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: encodedKey,
	}
	return pem.EncodeToMemory(block), nil
}

// WriteCertificatesDER writes X.509 certificates in DER format to the given [io.Writer].
func WriteCertificatesDER(out io.Writer, certificates []*x509.Certificate) error {
	encoded := encodeCertificatesDER(certificates)
	_, err := out.Write(encoded)
	return err
}

// WriteCertificatesDERFile writes X.509 certificates in DER format to the given file.
func WriteCertificatesDERFile(filename string, certificates []*x509.Certificate, perm os.FileMode) error {
	encoded := encodeCertificatesDER(certificates)
	return os.WriteFile(filename, encoded, perm)
}

func encodeCertificatesDER(certificates []*x509.Certificate) []byte {
	encoded := make([]byte, 0)
	for _, certificate := range certificates {
		encoded = append(encoded, certificate.Raw...)
	}
	return encoded
}

func encodeKeyDER(key crypto.PrivateKey) ([]byte, error) {
	encoded, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		algorithm, _ := keys.AlgorithmFromKey(keys.KeyFromPrivate(key).Public())
		return nil, fmt.Errorf("failed to marshal private key of type '%s' (cause: %w)", algorithm, err)
	}
	return encoded, nil
}

// FetchCertificates fetches X.509 certificates from the given URL.
func FetchCertificates(url string) ([]*x509.Certificate, error) {
	bytes, err := fetchBytes(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch certificates from url '%s' (cause: %w)", url, err)
	}
	decoded, err := decodeCertificates(bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to decode certificates from url '%s' (cause: %w)", url, err)
	}
	return decoded, nil
}

func fetchBytes(url string) ([]byte, error) {
	rsp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer rsp.Body.Close()
	if rsp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http status: %s", rsp.Status)
	}
	bytes, err := io.ReadAll(rsp.Body)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

// ServerCertificates gets the X.509 certificates used for encrypting the connection to the given server.
//
// The server protocol must be TLS based (e.g. https, ldaps). The certificates are retrieved during the TLS handshake.
func ServerCertificates(network string, addr string) ([]*x509.Certificate, error) {
	conn, err := tls.Dial(network, addr, &tls.Config{InsecureSkipVerify: true, VerifyPeerCertificate: verifyPeerCertificate})
	if conn != nil {
		defer conn.Close()
	}
	if err == nil {
		return nil, fmt.Errorf("failed to retrieve server certificates (%s:%s)", network, addr)
	}
	cve, ok := err.(*tls.CertificateVerificationError)
	if !ok {
		return nil, err
	}
	return cve.UnverifiedCertificates, nil
}

func verifyPeerCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	err := tls.CertificateVerificationError{}
	err.UnverifiedCertificates = make([]*x509.Certificate, 0)
	for _, rawCert := range rawCerts {
		decodedCerts, _ := decodeCertificates(rawCert)
		if decodedCerts != nil {
			err.UnverifiedCertificates = append(err.UnverifiedCertificates, decodedCerts...)
		}
	}
	err.Err = fmt.Errorf("%d peer certifcates received", len(err.UnverifiedCertificates))
	return &err
}

func ExportPEM(out io.Writer, certificate *x509.Certificate, chain []*x509.Certificate, key crypto.PrivateKey) error {
	zip := zip.NewWriter(out)
	if certificate != nil {
		err := exportCertificatePEM(zip, certificate)
		if err != nil {
			return nil
		}
	}
	if len(chain) > 0 {
		err := exportChainsPEM(zip, chain)
		if err != nil {
			return nil
		}
	}
	if key != nil {
		err := exportKeyPEM(zip, key)
		if err != nil {
			return nil
		}
	}
	err := zip.Close()
	if err != nil {
		return fmt.Errorf("failed to write PEM archive (cause: %w)", err)
	}
	return nil
}

func exportCertificatePEM(zip *zip.Writer, certificate *x509.Certificate) error {
	file, err := zip.Create("cert.pem")
	if err != nil {
		return fmt.Errorf("failed to create cert.pem file (cause: %w)", err)
	}
	err = WriteCertificatesPEM(file, []*x509.Certificate{certificate})
	if err != nil {
		return fmt.Errorf("failed to wirte cert.pem file (cause: %w)", err)
	}
	return nil
}

func exportChainsPEM(zip *zip.Writer, chain []*x509.Certificate) error {
	if IsRoot(chain[len(chain)-1]) {
		err := exportChainPEM(zip, "fullchain.pem", chain)
		if err != nil {
			return nil
		}
		if len(chain) > 1 {
			err := exportChainPEM(zip, "chain.pem", chain[:len(chain)-1])
			if err != nil {
				return nil
			}
		}
	} else {
		err := exportChainPEM(zip, "chain.pem", chain)
		if err != nil {
			return nil
		}
	}
	return nil
}

func exportChainPEM(zip *zip.Writer, name string, chain []*x509.Certificate) error {
	file, err := zip.Create(name)
	if err != nil {
		return fmt.Errorf("failed to create %s file (cause: %w)", name, err)
	}
	err = WriteCertificatesPEM(file, chain)
	if err != nil {
		return fmt.Errorf("failed to write %s file (cause: %w)", name, err)
	}
	return nil
}

func exportKeyPEM(zip *zip.Writer, key crypto.PrivateKey) error {
	file, err := zip.Create("key.pem")
	if err != nil {
		return fmt.Errorf("failed to create key.pem file (cause: %w)", err)
	}
	encoded, err := encodeKeyPEM(key)
	if err != nil {
		return err
	}
	_, err = file.Write(encoded)
	if err != nil {
		return fmt.Errorf("failed to write key.pem file (cause: %w)", err)
	}
	return nil
}

func ExportDER(out io.Writer, certificate *x509.Certificate, chain []*x509.Certificate, key crypto.PrivateKey) error {
	zip := zip.NewWriter(out)
	if certificate != nil {
		err := exportCertificateDER(zip, certificate)
		if err != nil {
			return nil
		}
	}
	if len(chain) > 0 {
		err := exportChainsDER(zip, chain)
		if err != nil {
			return nil
		}
	}
	if key != nil {
		err := exportKeyDER(zip, key)
		if err != nil {
			return nil
		}
	}
	err := zip.Close()
	if err != nil {
		return fmt.Errorf("failed to write DER archive (cause: %w)", err)
	}
	return nil
}

func exportCertificateDER(zip *zip.Writer, certificate *x509.Certificate) error {
	file, err := zip.Create("cert.der")
	if err != nil {
		return fmt.Errorf("failed to create cert.der file (cause: %w)", err)
	}
	err = WriteCertificatesDER(file, []*x509.Certificate{certificate})
	if err != nil {
		return fmt.Errorf("failed to wirte cert.der file (cause: %w)", err)
	}
	return nil
}

func exportChainsDER(zip *zip.Writer, chain []*x509.Certificate) error {
	if IsRoot(chain[len(chain)-1]) {
		err := exportChainDER(zip, "fullchain.der", chain)
		if err != nil {
			return nil
		}
		if len(chain) > 1 {
			err := exportChainDER(zip, "chain.der", chain[:len(chain)-1])
			if err != nil {
				return nil
			}
		}
	} else {
		err := exportChainDER(zip, "chain.der", chain)
		if err != nil {
			return nil
		}
	}
	return nil
}

func exportChainDER(zip *zip.Writer, name string, chain []*x509.Certificate) error {
	file, err := zip.Create(name)
	if err != nil {
		return fmt.Errorf("failed to create %s file (cause: %w)", name, err)
	}
	err = WriteCertificatesDER(file, chain)
	if err != nil {
		return fmt.Errorf("failed to write %s file (cause: %w)", name, err)
	}
	return nil
}

func exportKeyDER(zip *zip.Writer, key crypto.PrivateKey) error {
	file, err := zip.Create("key.der")
	if err != nil {
		return fmt.Errorf("failed to create key.der file (cause: %w)", err)
	}
	encoded, err := encodeKeyDER(key)
	if err != nil {
		return err
	}
	_, err = file.Write(encoded)
	if err != nil {
		return fmt.Errorf("failed to write key.der file (cause: %w)", err)
	}
	return nil
}

func ExportPKCS12(out io.Writer, certificate *x509.Certificate, chain []*x509.Certificate, key crypto.PrivateKey, password string) error {
	encoded, err := pkcs12.Modern.Encode(key, certificate, chain, password)
	if err != nil {
		return fmt.Errorf("failed to encode PKCS12 (cause: %w)", err)
	}
	_, err = out.Write(encoded)
	return err
}
