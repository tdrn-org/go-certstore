// Copyright (C) 2023 Holger de Carne and contributors
//
// This software may be modified and distributed under the terms
// of the MIT license.  See the LICENSE file for details.

package keys

import (
	"crypto"
	algorithm "crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
)

// Name of the ECDSA key provider.
const ECDSAProviderName = "ECDSA"

// ECDSAKeyPair provides the KeyPair interface for ECDSA keys.
type ECDSAKeyPair struct {
	key *algorithm.PrivateKey
}

// NewECDSAKeyPair creates a new ECDSA key pair for the given curve.
func NewECDSAKeyPair(curve elliptic.Curve) (KeyPair, error) {
	key, err := algorithm.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, err
	}
	return &ECDSAKeyPair{key: key}, nil
}

// Public returns the public key of the ECDSA key pair.
func (keypair *ECDSAKeyPair) Public() crypto.PublicKey {
	return keypair.key.Public()
}

// Private returns the private key of the ECDSA key pair.
func (keypair *ECDSAKeyPair) Private() crypto.PrivateKey {
	return keypair.key
}

// ECDSAKeyPairFactory provides the KeyPairFactory interface for ECDSA keys.
type ECDSAKeyPairFactory struct {
	curve elliptic.Curve
}

// NewECDSAKeyPairFactory creates a new ECDSA key pair factory for the given curve.
func NewECDSAKeyPairFactory(curve elliptic.Curve) KeyPairFactory {
	return &ECDSAKeyPairFactory{curve: curve}
}

// Name returns the name of this ECDSA key pair factory.
func (factory *ECDSAKeyPairFactory) Name() string {
	return ECDSAProviderName + " " + factory.curve.Params().Name
}

// New generates a new ECDSA key pair
func (factory *ECDSAKeyPairFactory) New() (KeyPair, error) {
	return NewECDSAKeyPair(factory.curve)
}

// ECDSAKeyPairFactories returns key pair factories for the standard ECDSA curves (P224, P256, P384, P521).
func ECDSAKeyPairFactories() []KeyPairFactory {
	return []KeyPairFactory{
		NewECDSAKeyPairFactory(elliptic.P224()),
		NewECDSAKeyPairFactory(elliptic.P256()),
		NewECDSAKeyPairFactory(elliptic.P384()),
		NewECDSAKeyPairFactory(elliptic.P521()),
	}
}
