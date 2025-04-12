// Copyright (C) 2023-2025 Holger de Carne and contributors
//
// This software may be modified and distributed under the terms
// of the MIT license.  See the LICENSE file for details.

package keys_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tdrn-org/go-certstore/keys"
)

func TestPublicEquals(t *testing.T) {
	ecdsaPrivateKey, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	require.NoError(t, err)
	ed25519PublicKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// ecdsa
	require.True(t, keys.PublicsEqual(&ecdsaPrivateKey.PublicKey, &ecdsaPrivateKey.PublicKey))
	require.False(t, keys.PublicsEqual(&ecdsaPrivateKey.PublicKey, ed25519PublicKey))
	require.False(t, keys.PublicsEqual(&ecdsaPrivateKey.PublicKey, &rsaPrivateKey.PublicKey))

	// ed25519
	require.False(t, keys.PublicsEqual(ed25519PublicKey, &ecdsaPrivateKey.PublicKey))
	require.True(t, keys.PublicsEqual(ed25519PublicKey, ed25519PublicKey))
	require.False(t, keys.PublicsEqual(ed25519PublicKey, &rsaPrivateKey.PublicKey))

	// rsa
	require.False(t, keys.PublicsEqual(&rsaPrivateKey.PublicKey, &ecdsaPrivateKey.PublicKey))
	require.False(t, keys.PublicsEqual(&rsaPrivateKey.PublicKey, ed25519PublicKey))
	require.True(t, keys.PublicsEqual(&rsaPrivateKey.PublicKey, &rsaPrivateKey.PublicKey))
}

func TestPrivateEquals(t *testing.T) {
	ecdsaPrivateKey, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	require.NoError(t, err)
	_, ed25519PrivateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// ecdsa
	require.True(t, keys.PrivatesEqual(ecdsaPrivateKey, ecdsaPrivateKey))
	require.False(t, keys.PrivatesEqual(ecdsaPrivateKey, ed25519PrivateKey))
	require.False(t, keys.PrivatesEqual(ecdsaPrivateKey, rsaPrivateKey))

	// ed25519
	require.False(t, keys.PrivatesEqual(ed25519PrivateKey, ecdsaPrivateKey))
	require.True(t, keys.PrivatesEqual(ed25519PrivateKey, ed25519PrivateKey))
	require.False(t, keys.PrivatesEqual(ed25519PrivateKey, rsaPrivateKey))

	// rsa
	require.False(t, keys.PrivatesEqual(rsaPrivateKey, ecdsaPrivateKey))
	require.False(t, keys.PrivatesEqual(rsaPrivateKey, ed25519PrivateKey))
	require.True(t, keys.PrivatesEqual(rsaPrivateKey, rsaPrivateKey))
}

func TestPublicFromECDSA(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	require.NoError(t, err)
	require.True(t, keys.PublicsEqual(&privateKey.PublicKey, keys.PublicFromPrivate(privateKey)))
}

func TestPublicFromED25519(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	require.True(t, keys.PublicsEqual(publicKey, keys.PublicFromPrivate(privateKey)))
}

func TestPublicFromRSA(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	require.True(t, keys.PublicsEqual(&privateKey.PublicKey, keys.PublicFromPrivate(privateKey)))
}

func TestKeyFromPrivateECDSA(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	require.NoError(t, err)
	key := keys.KeyFromPrivate(privateKey)
	checkKey(t, key, &privateKey.PublicKey, crypto.SHA256)
}

func TestKeyFromPrivateED25519(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	key := keys.KeyFromPrivate(privateKey)
	checkKey(t, key, publicKey, 0)
}

func TestKeyFromPrivateRSA(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	key := keys.KeyFromPrivate(privateKey)
	checkKey(t, key, &privateKey.PublicKey, crypto.SHA256)
}

func checkKey(t *testing.T, key keys.Key, publicKey crypto.PublicKey, hash crypto.Hash) {
	require.True(t, keys.PublicsEqual(publicKey, key.Public()))
	message := []byte("secret message")
	digest := message
	if hash != 0 {
		digest = hash.New().Sum(message)[:hash.Size()]
	}
	signature, err := key.Sign(rand.Reader, digest, hash)
	require.NoError(t, err)
	require.True(t, key.Verify(signature, digest, hash))
}

func TestAlgs(t *testing.T) {
	for _, alg := range keys.Algs() {
		algFromName, err := keys.AlgorithmFromString(alg.String())
		require.NoError(t, err)
		require.Equal(t, alg, algFromName)
		fmt.Printf("Generating %s...\n", alg)
		start := time.Now()
		kpf := alg.NewKeyPairFactory()
		require.NotNil(t, kpf)
		require.Equal(t, alg, kpf.Alg())
		keypair, err := kpf.New()
		elapsed := time.Since(start)
		fmt.Printf(" (took: %s)\n", elapsed)
		require.NoError(t, err)
		require.NotNil(t, keypair)
		require.Equal(t, alg, keypair.Alg())
		require.NotNil(t, keypair.Private())
		require.NotNil(t, keypair.Public())
		algFromKey, err := keys.AlgorithmFromKey(keypair.Public())
		require.NoError(t, err)
		require.Equal(t, alg, algFromKey)
	}
}
