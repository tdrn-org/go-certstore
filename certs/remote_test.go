// Copyright (C) 2023 Holger de Carne and contributors
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

	"github.com/hdecarne-github/go-certstore/certs"
	"github.com/hdecarne-github/go-certstore/keys"
	"github.com/stretchr/testify/require"
)

func TestRemoteCertificateFactory(t *testing.T) {
	kpf := keys.ECDSA224.NewKeyPairFactory()
	requestTemplate := newRemoteTestCertificateRequestTemplate("TestRemoteCertificateFactory")
	crf := certs.NewRemoteCertificateRequestFactory(requestTemplate, kpf)
	_, request, err := crf.New()
	require.NoError(t, err)
	rootTemplate := newRemoteTestRootCertificateTemplate(request.Subject.CommonName)
	rootCF := certs.NewLocalCertificateFactory(rootTemplate, kpf, nil, nil)
	rootPrivateKey, root, err := rootCF.New()
	require.NoError(t, err)
	template := newRemoteTestCertificateTemplate(request.Subject.CommonName)
	cf := certs.NewRemoteCertificateFactory(template, request, root, rootPrivateKey)
	require.NotNil(t, cf)
	require.Equal(t, "Remote", cf.Name())
	privateKey, certificate, err := cf.New()
	require.NoError(t, err)
	require.Nil(t, privateKey)
	require.NotNil(t, certificate)
}

func TestRemoteCertificateRequestFactory(t *testing.T) {
	template := newRemoteTestCertificateRequestTemplate("TestRemoteCertificateRequestFactory")
	crf := certs.NewRemoteCertificateRequestFactory(template, keys.ECDSA224.NewKeyPairFactory())
	require.NotNil(t, crf)
	require.Equal(t, "Remote", crf.Name())
	privateKey, request, err := crf.New()
	require.NoError(t, err)
	require.NotNil(t, privateKey)
	require.NotNil(t, request)
}

func newRemoteTestCertificateTemplate(cn string) *x509.Certificate {
	now := time.Now()
	return &x509.Certificate{
		Subject:   pkix.Name{CommonName: cn},
		NotBefore: now,
		NotAfter:  now.AddDate(0, 0, 1),
	}
}

func newRemoteTestCertificateRequestTemplate(cn string) *x509.CertificateRequest {
	return &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn},
	}
}

func newRemoteTestRootCertificateTemplate(cn string) *x509.Certificate {
	now := time.Now()
	return &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            2,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		NotBefore:             now,
		NotAfter:              now.AddDate(0, 0, 1),
	}
}
