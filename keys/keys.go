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
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"
	"reflect"
)

// KeyPair interface provides unified access to a key pair.
type KeyPair interface {
	// Name returns this [KeyPair]'s algorithm.
	Alg() Algorithm
	// Private returns the private key of a key pair.
	Private() crypto.PrivateKey
	// Public returns the public key of a key pair.
	Public() crypto.PublicKey
}

// KeyPairFactory interface provides a unified way to create key pairs.
type KeyPairFactory interface {
	// Name returns this [KeyPairFactory]'s algorithm.
	Alg() Algorithm
	// New generates a new key pair.
	New() (KeyPair, error)
}

// Key interface provides a unified way to key related serivces like [crypto.Signer].
type Key interface {
	crypto.Signer
	Verify(signature []byte, digest []byte, opts crypto.SignerOpts) bool
}

// KeyFromPrivate wraps the given private key into a Key interface.
func KeyFromPrivate(privateKey crypto.PrivateKey) Key {
	ecdsaKey, ok := privateKey.(*ecdsa.PrivateKey)
	if ok {
		return wrapECDSAKey(ecdsaKey)
	}
	ed25519Key, ok := privateKey.(ed25519.PrivateKey)
	if ok {
		return wrapED25519Key(ed25519Key)
	}
	rsaKey, ok := privateKey.(*rsa.PrivateKey)
	if ok {
		return wrapRSAKey(rsaKey)
	}
	panic("unexpected private key type")
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

type Algorithm uint

const (
	RSA2048  Algorithm = 1
	RSA3072  Algorithm = 2
	RSA4096  Algorithm = 3
	RSA8192  Algorithm = 4
	ECDSA224 Algorithm = 5
	ECDSA256 Algorithm = 6
	ECDSA384 Algorithm = 7
	ECDSA521 Algorithm = 8
	ED25519  Algorithm = 9
)

// Algs returns the known algorithms.
func Algs() []Algorithm {
	return []Algorithm{
		RSA2048,
		RSA3072,
		RSA4096,
		RSA8192,
		ECDSA224,
		ECDSA256,
		ECDSA384,
		ECDSA521,
		ED25519,
	}
}

const unknownAlgorithmPattern = "uknown algorithm (%d)"

// Name gets the algorithm's name.
func (algorithm Algorithm) Name() string {
	switch algorithm {
	case RSA2048:
		return "RSA2048"
	case RSA3072:
		return "RSA3072"
	case RSA4096:
		return "RSA4095"
	case RSA8192:
		return "RSA8192"
	case ECDSA224:
		return "ECDSA224"
	case ECDSA256:
		return "ECDSA256"
	case ECDSA384:
		return "ECDSA384"
	case ECDSA521:
		return "ECDSA521"
	case ED25519:
		return "ED25519"
	}
	panic(fmt.Sprintf(unknownAlgorithmPattern, algorithm))
}

// NewKeyPairFactory gets the [KeyPairFactory] for the given algorithm.
func (alg Algorithm) NewKeyPairFactory() KeyPairFactory {
	switch alg {
	case RSA2048:
		return newRSAKeyPairFactory(alg, 2048)
	case RSA3072:
		return newRSAKeyPairFactory(alg, 3072)
	case RSA4096:
		return newRSAKeyPairFactory(alg, 4096)
	case RSA8192:
		return newRSAKeyPairFactory(alg, 8192)
	case ECDSA224:
		return newECDSAKeyPairFactory(alg, elliptic.P224())
	case ECDSA256:
		return newECDSAKeyPairFactory(alg, elliptic.P256())
	case ECDSA384:
		return newECDSAKeyPairFactory(alg, elliptic.P384())
	case ECDSA521:
		return newECDSAKeyPairFactory(alg, elliptic.P521())
	case ED25519:
		return newED25519KeyPairFactory()
	}
	panic(fmt.Sprintf(unknownAlgorithmPattern, alg))
}
