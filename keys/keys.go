// Copyright (C) 2023 Holger de Carne and contributors
//
// This software may be modified and distributed under the terms
// of the MIT license.  See the LICENSE file for details.

// Package keys implements a unified interface for key handling.
//
// The key types [crypto/ecdsa], [crypto/ed25519], [crypto/rsa] are supported.
package keys

import (
	"crypto"
	"reflect"
)

// KeyPair interface provides unified access to a key pair.
type KeyPair interface {
	// Private returns the private key of a key pair.
	Private() crypto.PrivateKey
	// Public returns the public key of a key pair.
	Public() crypto.PublicKey
}

// KeyPairFactory interface provides a unified way to create key pairs.
type KeyPairFactory interface {
	// Name returns the name of this factory.
	Name() string
	// New generates a new key pair.
	New() (KeyPair, error)
}

// PublicsEqual checks whether the two given public keys are equal.
func PublicsEqual(publicKey1 crypto.PublicKey, publicKey2 crypto.PublicKey) bool {
	return reflect.ValueOf(publicKey1).MethodByName("Equal").Call([]reflect.Value{reflect.ValueOf(publicKey2)})[0].Bool()
}

// PrivatesEqual checks whether the two given private keys are equal.
func PrivatesEqual(privateKey1 crypto.PrivateKey, privateKey2 crypto.PrivateKey) bool {
	return reflect.ValueOf(privateKey1).MethodByName("Equal").Call([]reflect.Value{reflect.ValueOf(privateKey2)})[0].Bool()
}

// PublicFromPrivate gets the public key associated with the given private key.
func PublicFromPrivate(privateKey crypto.PrivateKey) crypto.PublicKey {
	publicKey, _ := reflect.ValueOf(privateKey).MethodByName("Public").Call([]reflect.Value{})[0].Interface().(crypto.PublicKey)
	return publicKey
}

var providerNames = []string{}
var providerKeyPairFactories = make(map[string][]KeyPairFactory, 0)
var keyPairFactories = make(map[string]KeyPairFactory, 0)

// Providers returns the known key providers (ECDSA, ED25519, RSA).
func Providers() []string {
	names := providerNames
	return names
}

// ProviderKeyPairFactories returns the [KeyPairFactory] instances for the given key provider.
func ProviderKeyPairFactories(provider string) []KeyPairFactory {
	return providerKeyPairFactories[provider]
}

// ProviderKeyPairFactory returns the [KeyPairFactory] instance for the given key pair factory name.
func ProviderKeyPairFactory(keyPairFactoryName string) KeyPairFactory {
	return keyPairFactories[keyPairFactoryName]
}

func init() {
	providerNames = append(providerNames, ecdsaProviderName, ed25519ProviderName, rsaProviderName)
	initKPFs(ecdsaProviderName, ecdsaKeyPairFactories())
	initKPFs(ed25519ProviderName, ed25519KeyPairFactories())
	initKPFs(rsaProviderName, rsaKeyPairFactories())
}

func initKPFs(provider string, kpfs []KeyPairFactory) {
	providerKeyPairFactories[provider] = kpfs
	for _, kpf := range kpfs {
		keyPairFactories[kpf.Name()] = kpf
	}
}
