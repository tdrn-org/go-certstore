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
const testKeyAlg = keys.ECDSA256

func TestNewStore(t *testing.T) {
	registry, err := store.NewStore(storage.NewMemoryStorage(testVersionLimit))
	require.NoError(t, err)
	require.NotNil(t, registry)
	require.Equal(t, "Registry[memory://]", registry.Name())
}

func TestCreateCertificate(t *testing.T) {
	name := "TestCreateCertificate"
	user := name + "User"
	registry, err := store.NewStore(storage.NewMemoryStorage(testVersionLimit))
	require.NoError(t, err)
	factory := newTestRootCertificateFactory(name)
	createdName, err := registry.CreateCertificate(name, factory, user)
	require.NoError(t, err)
	require.Equal(t, name, createdName)
	entry, err := registry.Entry(createdName)
	require.NoError(t, err)
	require.NotNil(t, entry)
	require.True(t, entry.HasKey())
	entryKey := entry.Key(user)
	require.NotNil(t, entryKey)
	require.True(t, entry.HasCertificate())
	entryCertificate := entry.Certificate()
	require.NotNil(t, entryCertificate)
	require.True(t, entry.IsRoot())
	require.True(t, entry.CanIssue())
}

func TestCreateCertificateRequest(t *testing.T) {
	name := "TestCreateCertificateRequest"
	user := name + "User"
	registry, err := store.NewStore(storage.NewMemoryStorage(testVersionLimit))
	require.NoError(t, err)
	factory := newTestCertificateRequestFactory(name)
	createdName, err := registry.CreateCertificateRequest(name, factory, user)
	require.NoError(t, err)
	require.Equal(t, name, createdName)
	entry, err := registry.Entry(createdName)
	require.NoError(t, err)
	require.NotNil(t, entry)
	require.True(t, entry.HasKey())
	entryKey := entry.Key(user)
	require.NotNil(t, entryKey)
	require.True(t, entry.HasCertificateRequest())
	entryCertificate := entry.CertificateRequest()
	require.NotNil(t, entryCertificate)
}

func TestResetRevocationList(t *testing.T) {
	name := "TestResetRevocationList"
	user := name + "User"
	registry, err := store.NewStore(storage.NewMemoryStorage(testVersionLimit))
	require.NoError(t, err)
	certFactory := newTestRootCertificateFactory(name)
	createdName, err := registry.CreateCertificate(name, certFactory, user)
	require.NoError(t, err)
	entry, err := registry.Entry(createdName)
	require.NoError(t, err)
	require.False(t, entry.HasRevocationList())
	revocationListFactory := newTestRevocationListFactory()
	revocationList1, err := entry.ResetRevocationList(revocationListFactory, user)
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
	path, err := os.MkdirTemp("", "TestEntries*")
	require.NoError(t, err)
	defer os.RemoveAll(path)
	backend, err := storage.NewFSStorage(testVersionLimit, path)
	require.NoError(t, err)
	registry, err := store.NewStore(backend)
	require.NoError(t, err)
	user := "TestEntriesUser"
	start := time.Now()
	populateTestStore(t, registry, user, 10)
	elapsed := time.Since(start)
	fmt.Printf("Store populated (took: %s)\n", elapsed)
	entries, err := registry.Entries()
	require.NoError(t, err)
	totalCount := 0
	rootCount := 0
	start = time.Now()
	for {
		nextEntry, err := entries.Next()
		require.NoError(t, err)
		if nextEntry == nil {
			break
		}
		totalCount++
		if nextEntry.IsRoot() {
			rootCount++
		}
	}
	elapsed = time.Since(start)
	fmt.Printf("Store entries listed (took: %s)\n", elapsed)
	require.Equal(t, 1110, totalCount)
	require.Equal(t, 10, rootCount)
}

func TestMerge(t *testing.T) {
	path, err := os.MkdirTemp("", "TestMerge*")
	require.NoError(t, err)
	defer os.RemoveAll(path)
	backend, err := storage.NewFSStorage(testVersionLimit, path)
	require.NoError(t, err)
	registry, err := store.NewStore(backend)
	require.NoError(t, err)
	otherRegistry, err := store.NewStore(storage.NewMemoryStorage(testVersionLimit))
	require.NoError(t, err)
	user := "TestMergeUser"
	start := time.Now()
	populateTestStore(t, otherRegistry, user, 5)
	elapsed := time.Since(start)
	fmt.Printf("Store populated (took: %s)\n", elapsed)
	start = time.Now()
	err = registry.Merge(otherRegistry, user)
	require.NoError(t, err)
	elapsed = time.Since(start)
	fmt.Printf("Store merged (took: %s)\n", elapsed)
}

func populateTestStore(t *testing.T, registry *store.Registry, user string, count int) {
	createTestRootEntries(t, registry, user, count)
}

func createTestRootEntries(t *testing.T, registry *store.Registry, user string, count int) {
	for i := 0; i < count; i++ {
		name := fmt.Sprintf("root%d", i+1)
		factory := newTestRootCertificateFactory(name)
		createdName, err := registry.CreateCertificate(name, factory, user)
		require.NoError(t, err)
		require.Equal(t, name, createdName)
		entry, err := registry.Entry(createdName)
		require.NoError(t, err)
		_, err = entry.ResetRevocationList(newTestRevocationListFactory(), user)
		require.NoError(t, err)
		createTestIntermediateEntries(t, registry, createdName, user, count)
	}
}

func createTestIntermediateEntries(t *testing.T, registry *store.Registry, issuerName string, user string, count int) {
	issuerEntry, err := registry.Entry(issuerName)
	require.NoError(t, err)
	issuerCert := issuerEntry.Certificate()
	issuerKey := issuerEntry.Key(user)
	for i := 0; i < count; i++ {
		name := fmt.Sprintf("%s:intermediate%d", issuerName, i+1)
		factory := newTestIntermediateCertificateFactory(name, issuerCert, issuerKey)
		createdName, err := registry.CreateCertificate(name, factory, user)
		require.NoError(t, err)
		require.Equal(t, name, createdName)
		createTestLeafEntries(t, registry, createdName, user, count)
	}
}

func createTestLeafEntries(t *testing.T, registry *store.Registry, issuerName string, user string, count int) {
	issuerEntry, err := registry.Entry(issuerName)
	require.NoError(t, err)
	issuerCert := issuerEntry.Certificate()
	issuerKey := issuerEntry.Key(user)
	for i := 0; i < count; i++ {
		name := fmt.Sprintf("%s:leaf%d", issuerName, i+1)
		factory := newTestLeafCertificateFactory(name, issuerCert, issuerKey)
		createdName, err := registry.CreateCertificate(name, factory, user)
		require.NoError(t, err)
		require.Equal(t, name, createdName)
	}
}

func newTestRootCertificateFactory(cn string) certs.CertificateFactory {
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
	return certs.NewLocalCertificateFactory(template, testKeyAlg.NewKeyPairFactory(), nil, nil)
}

func newTestIntermediateCertificateFactory(cn string, parent *x509.Certificate, signer crypto.PrivateKey) certs.CertificateFactory {
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
		KeyUsage:              x509.KeyUsageCertSign,
		NotBefore:             now,
		NotAfter:              now.AddDate(0, 0, 1),
	}
	return certs.NewLocalCertificateFactory(template, testKeyAlg.NewKeyPairFactory(), parent, signer)
}

func newTestLeafCertificateFactory(cn string, parent *x509.Certificate, signer crypto.PrivateKey) certs.CertificateFactory {
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		BasicConstraintsValid: true,
		IsCA:                  false,
		MaxPathLen:            -1,
		NotBefore:             now,
		NotAfter:              now.AddDate(0, 0, 1),
	}
	return certs.NewLocalCertificateFactory(template, testKeyAlg.NewKeyPairFactory(), parent, signer)
}

func newTestCertificateRequestFactory(cn string) certs.CertificateRequestFactory {
	template := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn},
	}
	return certs.NewRemoteCertificateRequestFactory(template, testKeyAlg.NewKeyPairFactory())
}

func newTestRevocationListFactory() certs.RevocationListFactory {
	now := time.Now()
	template := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: now,
		NextUpdate: now.AddDate(0, 1, 0),
	}
	return certs.NewLocalRevocationListFactory(template)
}
