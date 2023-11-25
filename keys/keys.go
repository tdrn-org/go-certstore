// Copyright (C) 2023 Holger de Carne and contributors
//
// This software may be modified and distributed under the terms
// of the MIT license.  See the LICENSE file for details.

// Package keys implements a unified interface for key handling.
package keys

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
)

// KeyPair interface provides access to the private key and its accompanyinng public key.
type KeyPair interface {
	// Public returns the public key of a key pair.
	Public() crypto.PublicKey
	// Private returns the private key of a key pair.
	Private() crypto.PrivateKey
}

// KeyPairFactory interface provides a generic way to create a key pair.
type KeyPairFactory interface {
	// Name returns the name of this factory.
	Name() string
	// New creates a new key pair.
	New() (KeyPair, error)
}

// PublicsEqual checks whether the two given public keys are equal.
func PublicsEqual(key1 crypto.PublicKey, key2 crypto.PublicKey) bool {
	ecdsaKey1, ok := key1.(*ecdsa.PublicKey)
	if ok {
		return ecdsaKey1.Equal(key2)
	}
	ed25519Key1, ok := key1.(ed25519.PublicKey)
	if ok {
		return ed25519Key1.Equal(key2)
	}
	rsaKey1, ok := key1.(*rsa.PublicKey)
	if ok {
		return rsaKey1.Equal(key2)
	}
	return false
}

// PublicsEqual checks whether the two given private keys are equal.
func PrivatesEqual(key1 crypto.PrivateKey, key2 crypto.PrivateKey) bool {
	ecdsaKey1, ok := key1.(*ecdsa.PrivateKey)
	if ok {
		return ecdsaKey1.Equal(key2)
	}
	ed25519Key1, ok := key1.(ed25519.PrivateKey)
	if ok {
		return ed25519Key1.Equal(key2)
	}
	rsaKey1, ok := key1.(*rsa.PrivateKey)
	if ok {
		return rsaKey1.Equal(key2)
	}
	return false
}

var providerNames = []string{}
var providerKeyPairFactories = make(map[string]func() []KeyPairFactory, 0)
var keyPairFactories = make(map[string]KeyPairFactory, 0)

// KeyProviders returns the known key providers (ECDSA, ED25519, RSA).
func Providers() []string {
	names := providerNames
	return names
}

// ProviderKeyPairFactories returns the standard keys for the given key provider.
func ProviderKeyPairFactories(provider string) []KeyPairFactory {
	return providerKeyPairFactories[provider]()
}

// ProviderKeyPairFactory returns the key pair factory corresponding to the given key pair factory name.
func ProviderKeyPairFactory(kpfName string) KeyPairFactory {
	return keyPairFactories[kpfName]
}

func init() {
	providerNames = append(providerNames, ECDSAProviderName, ED25519ProviderName, RSAProviderName)
	providerKeyPairFactories[ECDSAProviderName] = ECDSAKeyPairFactories
	for _, kpf := range ECDSAKeyPairFactories() {
		keyPairFactories[kpf.Name()] = kpf
	}
	providerKeyPairFactories[ED25519ProviderName] = ED25519KeyPairFactories
	for _, kpf := range ED25519KeyPairFactories() {
		keyPairFactories[kpf.Name()] = kpf
	}
	providerKeyPairFactories[RSAProviderName] = RSAKeyPairFactories
	for _, kpf := range RSAKeyPairFactories() {
		keyPairFactories[kpf.Name()] = kpf
	}
}
