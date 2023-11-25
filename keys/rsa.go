// Copyright (C) 2023 Holger de Carne and contributors
//
// This software may be modified and distributed under the terms
// of the MIT license.  See the LICENSE file for details.

package keys

import (
	"crypto"
	"crypto/rand"
	algorithm "crypto/rsa"
	"strconv"
)

// Name of the RSA key provider.
const RSAProviderName = "RSA"

// RSAKeyPair provides the KeyPair interface for RSA keys.
type RSAKeyPair struct {
	key *algorithm.PrivateKey
}

// NewRSAKeyPair creates a new RSA key pair for the given bit size.
func NewRSAKeyPair(bits int) (KeyPair, error) {
	key, err := algorithm.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	return &RSAKeyPair{key: key}, nil
}

// Public returns the public key of the RSA key pair.
func (keypair *RSAKeyPair) Public() crypto.PublicKey {
	return &keypair.key.PublicKey
}

// Private returns the private key of the RSA key pair.
func (keypair *RSAKeyPair) Private() crypto.PrivateKey {
	return keypair.key
}

// RSAKeyPairFactory provides the KeyPairFactory interface for RSA keys.
type RSAKeyPairFactory struct {
	bits int
}

// NewRSAKeyPairFactory creates a new RSA key pair factory for the given bit size.
func NewRSAKeyPairFactory(bits int) KeyPairFactory {
	return &RSAKeyPairFactory{bits: bits}
}

// Name returns the name of this RSA key pair factory.
func (factory *RSAKeyPairFactory) Name() string {
	return RSAProviderName + " " + strconv.Itoa(factory.bits)
}

// New generates a new RSA key pair
func (factory *RSAKeyPairFactory) New() (KeyPair, error) {
	return NewRSAKeyPair(factory.bits)
}

// RSAKeyPairFactories returns key pair factories for the standard RSA bit sizes (2048, 3072, 4096).
func RSAKeyPairFactories() []KeyPairFactory {
	return []KeyPairFactory{
		NewRSAKeyPairFactory(2048),
		NewRSAKeyPairFactory(3072),
		NewRSAKeyPairFactory(4096),
	}
}
