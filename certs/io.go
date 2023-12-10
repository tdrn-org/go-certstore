// Copyright (C) 2023 Holger de Carne and contributors
//
// This software may be modified and distributed under the terms
// of the MIT license.  See the LICENSE file for details.

package certs

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
)

// ReadCertificates reads X.509 certificates from the given file.
func ReadCertificates(filename string) ([]*x509.Certificate, error) {
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

// WriteCertificatesPEM writes X.509 certificates in PEM format to the given file.
func WriteCertificatesPEM(filename string, certificates []*x509.Certificate, perm os.FileMode) error {
	encoded := make([]byte, 0)
	for _, certificate := range certificates {
		block := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certificate.Raw,
		}
		encoded = append(encoded, pem.EncodeToMemory(block)...)
	}
	return os.WriteFile(filename, encoded, perm)
}

// WriteCertificatesDER writes X.509 certificates in DER format to the given file.
func WriteCertificatesDER(filename string, certificates []*x509.Certificate, perm os.FileMode) error {
	encoded := make([]byte, 0)
	for _, certificate := range certificates {
		encoded = append(encoded, certificate.Raw...)
	}
	return os.WriteFile(filename, encoded, perm)
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
