// Copyright (C) 2023-2024 Holger de Carne and contributors
//
// This software may be modified and distributed under the terms
// of the MIT license.  See the LICENSE file for details.

package certs_test

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tdrn-org/go-certstore/certs"
	"github.com/tdrn-org/go-certstore/keys"
)

func TestLocalCertificateFactory(t *testing.T) {
	// self-signed
	template1 := newLocalTestCertificateTemplate("Test1")
	template1.IsCA = true
	template1.KeyUsage = template1.KeyUsage | x509.KeyUsageCertSign
	cf1 := certs.NewLocalCertificateFactory(template1, keys.ECDSA224.NewKeyPairFactory(), nil, nil)
	require.NotNil(t, cf1)
	require.Equal(t, "Local", cf1.Name())
	privateKey1, cert1, err := cf1.New()
	require.NoError(t, err)
	require.NotNil(t, privateKey1)
	require.NotNil(t, cert1)
	require.Equal(t, big.NewInt(1), cert1.SerialNumber)
	require.Equal(t, template1.Subject.Organization, cert1.Subject.Organization)
	// signed
	template2 := newLocalTestCertificateTemplate("Test2")
	cf2 := certs.NewLocalCertificateFactory(template2, keys.ECDSA224.NewKeyPairFactory(), cert1, privateKey1)
	require.NotNil(t, cf2)
	privateKey2, cert2, err := cf2.New()
	require.NoError(t, err)
	require.NotNil(t, privateKey2)
	require.NotNil(t, cert2)
	require.Equal(t, template2.Subject.Organization, cert2.Subject.Organization)
}
func TestLocalRevocationListFactory(t *testing.T) {
	issuerTemplate := newLocalTestCertificateTemplate("Issuer")
	issuerTemplate.IsCA = true
	issuerTemplate.KeyUsage = issuerTemplate.KeyUsage | x509.KeyUsageCRLSign
	issuerFactory := certs.NewLocalCertificateFactory(issuerTemplate, keys.ECDSA224.NewKeyPairFactory(), nil, nil)
	signer, issuer, err := issuerFactory.New()
	require.NoError(t, err)
	template := newLocalTestRevocationListEmplate(1)
	rlf := certs.NewLocalRevocationListFactory(template)
	revocationList, err := rlf.New(issuer, signer)
	require.NoError(t, err)
	require.NotNil(t, revocationList)
}

func newLocalTestCertificateTemplate(cn string) *x509.Certificate {
	now := time.Now()
	return &x509.Certificate{
		Subject:   pkix.Name{CommonName: cn},
		NotBefore: now,
		NotAfter:  now.AddDate(0, 0, 1),
	}
}

func newLocalTestRevocationListEmplate(number int64) *x509.RevocationList {
	now := time.Now()
	return &x509.RevocationList{
		Number:     big.NewInt(number),
		ThisUpdate: now,
		NextUpdate: now.AddDate(0, 1, 0),
	}
}
