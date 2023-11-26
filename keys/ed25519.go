// Copyright (C) 2023 Holger de Carne and contributors
//
// This software may be modified and distributed under the terms
// of the MIT license.  See the LICENSE file for details.

package keys

import (
	"crypto"
	algorithm "crypto/ed25519"
	"crypto/rand"

	"github.com/hdecarne-github/go-log"
	"github.com/rs/zerolog"
)

const ed25519ProviderName = "ED25519"

type ed25519KeyPair struct {
	public  algorithm.PublicKey
	private algorithm.PrivateKey
}

func (keypair *ed25519KeyPair) Public() crypto.PublicKey {
	return keypair.public
}

func (keypair *ed25519KeyPair) Private() crypto.PrivateKey {
	return keypair.private
}

// NewED25519KeyPair generates a new ED25519 key pair.
func NewED25519KeyPair() (KeyPair, error) {
	public, private, err := algorithm.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &ed25519KeyPair{public: public, private: private}, nil
}

type ed25519KeyPairFactory struct {
	logger *zerolog.Logger
}

func (factory *ed25519KeyPairFactory) Name() string {
	return ed25519ProviderName
}

func (factory *ed25519KeyPairFactory) New() (KeyPair, error) {
	factory.logger.Info().Msg("generating new ED25519 key pair...")
	return NewED25519KeyPair()
}

// NewED25519KeyPairFactory creates a new ED25519 key pair factory.
func NewED25519KeyPairFactory() KeyPairFactory {
	logger := log.RootLogger().With().Str("KeyPairFactory", ed25519ProviderName).Logger()
	return &ed25519KeyPairFactory{logger: &logger}
}

func ed25519KeyPairFactories() []KeyPairFactory {
	return []KeyPairFactory{
		NewED25519KeyPairFactory(),
	}
}
