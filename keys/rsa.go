// Copyright (C) 2023-2024 Holger de Carne and contributors
//
// This software may be modified and distributed under the terms
// of the MIT license.  See the LICENSE file for details.

package keys

import (
	"crypto"
	"crypto/rand"
	algorithm "crypto/rsa"
	"io"
	"log/slog"
)

type rsaKeyPair struct {
	alg Algorithm
	key *algorithm.PrivateKey
}

func (keypair *rsaKeyPair) Alg() Algorithm {
	return keypair.alg
}

func (keypair *rsaKeyPair) Public() crypto.PublicKey {
	return &keypair.key.PublicKey
}

func (keypair *rsaKeyPair) Private() crypto.PrivateKey {
	return keypair.key
}

func newRSAKeyPair(alg Algorithm, bits int) (KeyPair, error) {
	key, err := algorithm.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	return &rsaKeyPair{alg: alg, key: key}, nil
}

type rsaKeyPairFactory struct {
	alg    Algorithm
	bits   int
	logger *slog.Logger
}

func (factory *rsaKeyPairFactory) Alg() Algorithm {
	return factory.alg
}

func (factory *rsaKeyPairFactory) New() (KeyPair, error) {
	factory.logger.Info("generating new RSA key pair...")
	return newRSAKeyPair(factory.alg, factory.bits)
}

func newRSAKeyPairFactory(alg Algorithm, bits int) KeyPairFactory {
	logger := slog.With(slog.String("alg", alg.String()))
	return &rsaKeyPairFactory{alg: alg, bits: bits, logger: logger}
}

type rsaKey struct {
	key *algorithm.PrivateKey
}

func (wrapped *rsaKey) Public() crypto.PublicKey {
	return &wrapped.key.PublicKey
}

func (wrapped *rsaKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	hash := opts.HashFunc()
	return algorithm.SignPKCS1v15(rand, wrapped.key, hash, digest)
}

func (wrapped *rsaKey) Verify(signature []byte, digest []byte, opts crypto.SignerOpts) bool {
	return algorithm.VerifyPKCS1v15(&wrapped.key.PublicKey, opts.HashFunc(), digest, signature) == nil
}

func wrapRSAKey(key *algorithm.PrivateKey) Key {
	return &rsaKey{key: key}
}
