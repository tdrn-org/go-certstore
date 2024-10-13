// Copyright (C) 2023-2024 Holger de Carne and contributors
//
// This software may be modified and distributed under the terms
// of the MIT license.  See the LICENSE file for details.

package certs_test

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/hdecarne-github/go-certstore/certs"
	"github.com/hdecarne-github/go-certstore/keys"
	"github.com/stretchr/testify/require"
)

const testKeyAlg = keys.ECDSA256

func TestIsRootAndIsIssuedBy(t *testing.T) {
	rootKey, root := newTestRootCert(t, "root")
	intermediateKey, intermediate := newTestIntermediateCert(t, "intermediate", root, rootKey)
	_, leaf := newTestLeafCert(t, "leaf", intermediate, intermediateKey)
	require.True(t, certs.IsRoot(root))
	require.False(t, certs.IsRoot(intermediate))
	require.False(t, certs.IsRoot(leaf))
	require.True(t, certs.IsIssuedBy(intermediate, root))
	require.True(t, certs.IsIssuedBy(leaf, intermediate))
	require.False(t, certs.IsIssuedBy(leaf, root))
}

func newTestKeyPair(t *testing.T) keys.KeyPair {
	keyPair, err := testKeyAlg.NewKeyPairFactory().New()
	require.NoError(t, err)
	return keyPair
}

func newTestRootCert(t *testing.T, cn string) (crypto.PrivateKey, *x509.Certificate) {
	keyPair := newTestKeyPair(t)
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            2,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		NotBefore:             now,
		NotAfter:              now.AddDate(0, 0, 1),
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, keyPair.Public(), keyPair.Private())
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certBytes)
	require.NoError(t, err)
	return keyPair.Private(), cert
}

func newTestIntermediateCert(t *testing.T, cn string, parent *x509.Certificate, signer crypto.PrivateKey) (crypto.PrivateKey, *x509.Certificate) {
	keyPair := newTestKeyPair(t)
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixMilli()),
		Subject:               pkix.Name{CommonName: cn},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
		KeyUsage:              x509.KeyUsageCertSign,
		NotBefore:             now,
		NotAfter:              now.AddDate(0, 0, 1),
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, template, parent, keyPair.Public(), signer)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certBytes)
	require.NoError(t, err)
	return keyPair.Private(), cert
}

func newTestLeafCert(t *testing.T, cn string, parent *x509.Certificate, signer crypto.PrivateKey) (crypto.PrivateKey, *x509.Certificate) {
	keyPair := newTestKeyPair(t)
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixMilli()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    now,
		NotAfter:     now.AddDate(0, 0, 1),
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, template, parent, keyPair.Public(), signer)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certBytes)
	require.NoError(t, err)
	return keyPair.Private(), cert
}

func TestParseDN(t *testing.T) {
	dn := &pkix.Name{
		CommonName:         "CommonName",
		Locality:           []string{"Locality"},
		Country:            []string{"Country"},
		Organization:       []string{"Organization"},
		OrganizationalUnit: []string{"OrganizationUnit"},
		PostalCode:         []string{"PostalCode"},
		Province:           []string{"Province"},
		SerialNumber:       "SerialNumber",
		StreetAddress:      []string{"StreetAddress"},
	}
	parsed, err := certs.ParseDN(dn.String())
	require.NoError(t, err)
	require.NotNil(t, parsed)
	require.Equal(t, dn.String(), parsed.String())
}
