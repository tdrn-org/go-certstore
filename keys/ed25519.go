// Copyright (C) 2023-2024 Holger de Carne and contributors
//
// This software may be modified and distributed under the terms
// of the MIT license.  See the LICENSE file for details.

package keys

import (
	"crypto"
	algorithm "crypto/ed25519"
	"crypto/rand"
	"io"

	"github.com/hdecarne-github/go-log"
	"github.com/rs/zerolog"
)

type ed25519KeyPair struct {
	alg     Algorithm
	public  algorithm.PublicKey
	private algorithm.PrivateKey
}

func (keypair *ed25519KeyPair) Alg() Algorithm {
	return keypair.alg
}

func (keypair *ed25519KeyPair) Public() crypto.PublicKey {
	return keypair.public
}

func (keypair *ed25519KeyPair) Private() crypto.PrivateKey {
	return keypair.private
}

func newED25519KeyPair() (KeyPair, error) {
	public, private, err := algorithm.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &ed25519KeyPair{alg: ED25519, public: public, private: private}, nil
}

type ed25519KeyPairFactory struct {
	logger *zerolog.Logger
}

func (factory *ed25519KeyPairFactory) Alg() Algorithm {
	return ED25519
}

func (factory *ed25519KeyPairFactory) New() (KeyPair, error) {
	factory.logger.Info().Msg("generating new ED25519 key pair...")
	return newED25519KeyPair()
}

func newED25519KeyPairFactory() KeyPairFactory {
	logger := log.RootLogger().With().Str("Algorithm", ED25519.String()).Logger()
	return &ed25519KeyPairFactory{logger: &logger}
}

type ed25519Key struct {
	key algorithm.PrivateKey
}

func (wrapped *ed25519Key) Public() crypto.PublicKey {
	return wrapped.key.Public()
}

func (wrapped *ed25519Key) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return wrapped.key.Sign(rand, digest, opts)
}

func (wrapped *ed25519Key) Verify(signature []byte, digest []byte, opts crypto.SignerOpts) bool {
	return algorithm.Verify(wrapped.key.Public().(algorithm.PublicKey), digest, signature)
}

func wrapED25519Key(key algorithm.PrivateKey) Key {
	return &ed25519Key{key: key}
}
