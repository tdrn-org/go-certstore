// Copyright (C) 2023-2024 Holger de Carne and contributors
//
// This software may be modified and distributed under the terms
// of the MIT license.  See the LICENSE file for details.

package keys

import (
	"crypto"
	algorithm "crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"io"
	"log/slog"
)

type ecdsaKeyPair struct {
	alg Algorithm
	key *algorithm.PrivateKey
}

func (keypair *ecdsaKeyPair) Alg() Algorithm {
	return keypair.alg
}

func (keypair *ecdsaKeyPair) Public() crypto.PublicKey {
	return keypair.key.Public()
}

func (keypair *ecdsaKeyPair) Private() crypto.PrivateKey {
	return keypair.key
}

func newECDSAKeyPair(alg Algorithm, curve elliptic.Curve) (KeyPair, error) {
	key, err := algorithm.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, err
	}
	return &ecdsaKeyPair{alg: alg, key: key}, nil
}

type ecdsaKeyPairFactory struct {
	alg    Algorithm
	curve  elliptic.Curve
	logger *slog.Logger
}

func (factory *ecdsaKeyPairFactory) Alg() Algorithm {
	return factory.alg
}

func (factory *ecdsaKeyPairFactory) New() (KeyPair, error) {
	factory.logger.Info("generating new ECSDA key pair...")
	return newECDSAKeyPair(factory.alg, factory.curve)
}

func newECDSAKeyPairFactory(alg Algorithm, curve elliptic.Curve) KeyPairFactory {
	logger := slog.With(slog.String("alg", alg.String()))
	return &ecdsaKeyPairFactory{alg: alg, curve: curve, logger: logger}
}

type ecdsaKey struct {
	key *algorithm.PrivateKey
}

func (wrapped *ecdsaKey) Public() crypto.PublicKey {
	return &wrapped.key.PublicKey
}

func (wrapped *ecdsaKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return algorithm.SignASN1(rand, wrapped.key, opts.HashFunc().New().Sum(digest))
}

func (wrapped *ecdsaKey) Verify(signature []byte, digest []byte, opts crypto.SignerOpts) bool {
	return algorithm.VerifyASN1(&wrapped.key.PublicKey, digest, signature)
}

func wrapECDSAKey(key *algorithm.PrivateKey) Key {
	return &ecdsaKey{key: key}
}
