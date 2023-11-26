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

	"github.com/hdecarne-github/go-log"
	"github.com/rs/zerolog"
)

const rsaProviderName = "RSA"

type rsaKeyPair struct {
	key *algorithm.PrivateKey
}

func (keypair *rsaKeyPair) Public() crypto.PublicKey {
	return &keypair.key.PublicKey
}

func (keypair *rsaKeyPair) Private() crypto.PrivateKey {
	return keypair.key
}

// NewRSAKeyPair generates a new RSA key pair for the given bit size.
func NewRSAKeyPair(bits int) (KeyPair, error) {
	key, err := algorithm.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	return &rsaKeyPair{key: key}, nil
}

type rsaKeyPairFactory struct {
	bits   int
	name   string
	logger *zerolog.Logger
}

func (factory *rsaKeyPairFactory) Name() string {
	return factory.name
}

func (factory *rsaKeyPairFactory) New() (KeyPair, error) {
	factory.logger.Info().Msg("generating new RSA key pair...")
	return NewRSAKeyPair(factory.bits)
}

// NewRSAKeyPairFactory creates a new RSA key pair factory for the given bit size.
func NewRSAKeyPairFactory(bits int) KeyPairFactory {
	name := rsaProviderName + " " + strconv.Itoa(bits)
	logger := log.RootLogger().With().Str("KeyPairFactory", name).Logger()
	return &rsaKeyPairFactory{bits: bits, name: name, logger: &logger}
}

func rsaKeyPairFactories() []KeyPairFactory {
	return []KeyPairFactory{
		NewRSAKeyPairFactory(2048),
		NewRSAKeyPairFactory(3072),
		NewRSAKeyPairFactory(4096),
	}
}
