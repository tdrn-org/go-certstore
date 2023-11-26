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

	"github.com/hdecarne-github/go-log"
	"github.com/rs/zerolog"
)

const ecdsaProviderName = "ECDSA"

type ecdsaKeyPair struct {
	key *algorithm.PrivateKey
}

func (keypair *ecdsaKeyPair) Public() crypto.PublicKey {
	return keypair.key.Public()
}

func (keypair *ecdsaKeyPair) Private() crypto.PrivateKey {
	return keypair.key
}

// NewECDSAKeyPair generates a new ECDSA key pair for the given curve.
func NewECDSAKeyPair(curve elliptic.Curve) (KeyPair, error) {
	key, err := algorithm.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, err
	}
	return &ecdsaKeyPair{key: key}, nil
}

type ecdsaKeyPairFactory struct {
	curve  elliptic.Curve
	name   string
	logger *zerolog.Logger
}

func (factory *ecdsaKeyPairFactory) Name() string {
	return factory.name
}

func (factory *ecdsaKeyPairFactory) New() (KeyPair, error) {
	factory.logger.Info().Msg("generating new ECSDA key pair...")
	return NewECDSAKeyPair(factory.curve)
}

// NewECDSAKeyPairFactory creates a new ECDSA key pair factory for the given curve.
func NewECDSAKeyPairFactory(curve elliptic.Curve) KeyPairFactory {
	name := ecdsaProviderName + " " + curve.Params().Name
	logger := log.RootLogger().With().Str("KeyPairFactory", name).Logger()
	return &ecdsaKeyPairFactory{curve: curve, name: name, logger: &logger}
}

func ecdsaKeyPairFactories() []KeyPairFactory {
	return []KeyPairFactory{
		NewECDSAKeyPairFactory(elliptic.P224()),
		NewECDSAKeyPairFactory(elliptic.P256()),
		NewECDSAKeyPairFactory(elliptic.P384()),
		NewECDSAKeyPairFactory(elliptic.P521()),
	}
}
