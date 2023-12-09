// Copyright (C) 2023 Holger de Carne and contributors
//
// This software may be modified and distributed under the terms
// of the MIT license.  See the LICENSE file for details.

package certs_test

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"

	"github.com/hdecarne-github/go-certstore/certs"
	"github.com/hdecarne-github/go-certstore/keys"
	"github.com/stretchr/testify/require"
)

func TestRemoteCertificateRequestFactory(t *testing.T) {
	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			Organization: []string{"TestLocalCertificateFactory"},
		},
	}
	crf := certs.NewRemoteCertificateRequestFactory(template, keys.ECDSA224.NewKeyPairFactory())
	require.NotNil(t, crf)
	require.Equal(t, "Remote", crf.Name())
	privateKey, request, err := crf.New()
	require.NotNil(t, privateKey)
	require.NotNil(t, request)
	require.NoError(t, err)
}
