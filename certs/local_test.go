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
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(rand.Int63n(math.MaxInt64)),
		Subject: pkix.Name{
			Organization: []string{"TestLocalCertificateFactory"},
		},
		NotBefore: now,
		NotAfter:  now.Add(time.Hour),
	}
	cf := certs.NewLocalCertificateFactory(template, keys.ProviderKeyPairFactories("ECDSA")[0], nil, nil)
	require.NotNil(t, cf)
	require.Equal(t, "Local", cf.Name())
	privateKey, cert, err := cf.New()
	require.NotNil(t, privateKey)
	require.NotNil(t, cert)
	require.NoError(t, err)
}
