// Copyright (C) 2023 Holger de Carne and contributors
//
// This software may be modified and distributed under the terms
// of the MIT license.  See the LICENSE file for details.

package store_test

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"math"
	"math/big"
	"math/rand"
	"testing"
	"time"

	store "github.com/hdecarne-github/go-certstore"
	"github.com/hdecarne-github/go-certstore/certs"
	"github.com/hdecarne-github/go-certstore/keys"
	"github.com/hdecarne-github/go-certstore/storage"
	"github.com/stretchr/testify/require"
)

func TestNewStore(t *testing.T) {
	registry, err := store.NewStore(storage.NewMemoryStorage(2))
	require.NoError(t, err)
	require.NotNil(t, registry)
	require.Equal(t, "Registry[memory://]", registry.Name())
}

func TestCreateCertificate(t *testing.T) {
	factory := newCertificateFactory()
	registry, err := store.NewStore(storage.NewMemoryStorage(2))
	require.NoError(t, err)
	name := "TestCreateCertificate"
	user := name + "User"
	createdName, err := registry.CreateCertificate(name, factory, user)
	require.NoError(t, err)
	require.Equal(t, name, createdName)
	entry, err := registry.Entry(createdName)
	require.NoError(t, err)
	require.NotNil(t, entry)
	require.True(t, entry.HasKey())
	entryKey, err := entry.Key(user)
	require.NoError(t, err)
	require.NotNil(t, entryKey)
	require.True(t, entry.HasCertificate())
	entryCertificate := entry.Certificate()
	require.NotNil(t, entryCertificate)
	require.True(t, entry.IsRoot())
	require.True(t, entry.CanIssue())
}

func TestCreateCertificateRequest(t *testing.T) {
	factory := newCertificateRequestFactory()
	registry, err := store.NewStore(storage.NewMemoryStorage(2))
	require.NoError(t, err)
	name := "TestCreateCertificateRequest"
	user := name + "User"
	createdName, err := registry.CreateCertificateRequest(name, factory, user)
	require.NoError(t, err)
	require.Equal(t, name, createdName)
	entry, err := registry.Entry(createdName)
	require.NoError(t, err)
	require.NotNil(t, entry)
	require.True(t, entry.HasKey())
	entryKey, err := entry.Key(user)
	require.NoError(t, err)
	require.NotNil(t, entryKey)
	require.True(t, entry.HasCertificateRequest())
	entryCertificate := entry.CertificateRequest()
	require.NotNil(t, entryCertificate)
}

func TestResetRevocationList(t *testing.T) {
	factory := newCertificateFactory()
	registry, err := store.NewStore(storage.NewMemoryStorage(2))
	require.NoError(t, err)
	name := "TestResetRevocationList"
	user := name + "User"
	createdName, err := registry.CreateCertificate(name, factory, user)
	require.NoError(t, err)
	entry, err := registry.Entry(createdName)
	require.NoError(t, err)
	require.False(t, entry.HasRevocationList())
	key, err := entry.Key(user)
	require.NoError(t, err)
	rlf := newRevocationListFactory(entry.Certificate(), key)
	revocationList1, err := entry.ResetRevocationList(rlf, user)
	require.NoError(t, err)
	require.NotNil(t, revocationList1)
	entry, err = registry.Entry(createdName)
	require.NoError(t, err)
	require.True(t, entry.HasRevocationList())
	revocationList2 := entry.RevocationList()
	require.NotNil(t, revocationList2)
	require.Equal(t, revocationList1, revocationList2)
}

func newCertificateFactory() certs.CertificateFactory {
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(rand.Int63n(math.MaxInt64)),
		Subject: pkix.Name{
			Organization: []string{now.Local().String()},
		},
		IsCA:      true,
		KeyUsage:  x509.KeyUsageCRLSign,
		NotBefore: now,
		NotAfter:  now.Add(time.Hour),
	}
	return certs.NewLocalCertificateFactory(template, keys.ECDSA224.NewKeyPairFactory(), nil, nil)
}

func newCertificateRequestFactory() certs.CertificateRequestFactory {
	now := time.Now()
	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			Organization: []string{now.Local().String()},
		},
	}
	return certs.NewRemoteCertificateRequestFactory(template, keys.ECDSA224.NewKeyPairFactory())
}

func newRevocationListFactory(issuer *x509.Certificate, signer crypto.PrivateKey) certs.RevocationListFactory {
	now := time.Now()
	template := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: now,
		NextUpdate: now.Add(24 * time.Hour),
	}
	return certs.NewLocalRevocationListFactory(template, issuer, signer)
}
