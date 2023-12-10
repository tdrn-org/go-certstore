// Copyright (C) 2023 Holger de Carne and contributors
//
// This software may be modified and distributed under the terms
// of the MIT license.  See the LICENSE file for details.

package store_test

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"os"
	"testing"
	"time"

	store "github.com/hdecarne-github/go-certstore"
	"github.com/hdecarne-github/go-certstore/certs"
	"github.com/hdecarne-github/go-certstore/keys"
	"github.com/hdecarne-github/go-certstore/storage"
	"github.com/stretchr/testify/require"
)

const testVersionLimit storage.VersionLimit = 2

func TestNewStore(t *testing.T) {
	registry, err := store.NewStore(storage.NewMemoryStorage(testVersionLimit))
	require.NoError(t, err)
	require.NotNil(t, registry)
	require.Equal(t, "Registry[memory://]", registry.Name())
}

func TestCreateCertificate(t *testing.T) {
	name := "TestCreateCertificate"
	user := name + "User"
	factory := newCertificateFactory(nil, user)
	registry, err := store.NewStore(storage.NewMemoryStorage(testVersionLimit))
	require.NoError(t, err)
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
	registry, err := store.NewStore(storage.NewMemoryStorage(testVersionLimit))
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
	name := "TestResetRevocationList"
	user := name + "User"
	factory := newCertificateFactory(nil, user)
	registry, err := store.NewStore(storage.NewMemoryStorage(testVersionLimit))
	require.NoError(t, err)
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

func TestEntries(t *testing.T) {
	path, err := os.MkdirTemp("", "TestFSStorageNew*")
	require.NoError(t, err)
	defer os.RemoveAll(path)
	backend, err := storage.NewFSStorage(testVersionLimit, path)
	require.NoError(t, err)
	registry, err := store.NewStore(backend)
	require.NoError(t, err)
	user := "TestEntriesUser"
	// roots
	for i := 0; i < 10; i++ {
		createEntries(t, registry, "Root", nil, user)
	}
	// intermediates
	entries, err := registry.Entries()
	require.NoError(t, err)
	for {
		next, err := entries.Next()
		require.NoError(t, err)
		if next == nil {
			break
		}
		if next.IsRoot() {
			createEntries(t, registry, "Intermediate", next, user)
		}
	}
	// leafs
	entries, err = registry.Entries()
	require.NoError(t, err)
	for {
		next, err := entries.Next()
		require.NoError(t, err)
		if next == nil {
			break
		}
		if !next.IsRoot() {
			createEntries(t, registry, "Leaf", next, user)
		}
	}
}

func createEntries(t *testing.T, registry *store.Registry, name string, issuerEntry *store.RegistryEntry, user string) {
	issuerEntryName := ""
	if issuerEntry != nil {
		issuerEntryName = issuerEntry.Name()
	}
	for i := 0; i < 10; i++ {
		factory := newCertificateFactory(issuerEntry, user)
		_, err := registry.CreateCertificate(fmt.Sprintf("%s[%s:%d]", name, issuerEntryName, i), factory, user)
		require.NoError(t, err)
	}
}

func newCertificateFactory(issuerEntry *store.RegistryEntry, user string) certs.CertificateFactory {
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{now.Local().String()},
		},
		IsCA:      issuerEntry != nil,
		KeyUsage:  x509.KeyUsageCRLSign,
		NotBefore: now,
		NotAfter:  now.Add(time.Hour),
	}
	var issuer *x509.Certificate
	var signer crypto.PrivateKey
	if issuerEntry != nil {
		issuer = issuerEntry.Certificate()
		signer, _ = issuerEntry.Key(user)
	}
	return certs.NewLocalCertificateFactory(template, keys.ECDSA224.NewKeyPairFactory(), issuer, signer)
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
