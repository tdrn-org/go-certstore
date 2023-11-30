// Copyright (C) 2023 Holger de Carne and contributors
//
// This software may be modified and distributed under the terms
// of the MIT license.  See the LICENSE file for details.

package certs_test

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"math"
	"math/big"
	"math/rand"
	"testing"
	"time"

	"github.com/hdecarne-github/go-certstore/certs"
	"github.com/hdecarne-github/go-certstore/keys"
	"github.com/stretchr/testify/require"
)

func TestLocalCertificateFactory(t *testing.T) {
	// self-signed
	now1 := time.Now()
	template1 := &x509.Certificate{
		SerialNumber: big.NewInt(rand.Int63n(math.MaxInt64)),
		Subject: pkix.Name{
			Organization: []string{"Test1"},
		},
		NotBefore: now1,
		NotAfter:  now1.Add(time.Hour),
	}
	cf1 := certs.NewLocalCertificateFactory(template1, keys.ProviderKeyPairFactory("ECDSA P-224"), nil, nil)
	require.NotNil(t, cf1)
	require.Equal(t, "Local", cf1.Name())
	privateKey1, cert1, err := cf1.New()
	require.NotNil(t, privateKey1)
	require.NotNil(t, cert1)
	require.NoError(t, err)
	// signed
	now2 := time.Now()
	template2 := &x509.Certificate{
		SerialNumber: big.NewInt(rand.Int63n(math.MaxInt64)),
		Subject: pkix.Name{
			Organization: []string{"Test2"},
		},
		NotBefore: now2,
		NotAfter:  now2.Add(time.Hour),
	}
	cf2 := certs.NewLocalCertificateFactory(template2, keys.ProviderKeyPairFactory("ECDSA P-224"), cert1, privateKey1)
	require.NotNil(t, cf2)
	privateKey2, cert2, err := cf2.New()
	require.NotNil(t, privateKey2)
	require.NotNil(t, cert2)
	require.NoError(t, err)
}
