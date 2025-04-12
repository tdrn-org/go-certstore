// Copyright (C) 2023-2025 Holger de Carne and contributors
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
	rsaKey, ok := privateKey.(*rsa.PrivateKey)
	if ok {
		return wrapRSAKey(rsaKey)
	}
	ecdsaKey, ok := privateKey.(*ecdsa.PrivateKey)
	if ok {
		return wrapECDSAKey(ecdsaKey)
	}
	ed25519Key, ok := privateKey.(ed25519.PrivateKey)
	if ok {
		return wrapED25519Key(ed25519Key)
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
	UnknownAlgorithm Algorithm = 0
	RSA2048          Algorithm = 1 // RSA cipher 2048 bit key lenght
	RSA3072          Algorithm = 2 // RSA cipher 3072 bit key lenght
	RSA4096          Algorithm = 3 // RSA cipher 4096 bit key lenght
	RSA8192          Algorithm = 4 // RSA cipher 8192 bit key lenght
	ECDSA224         Algorithm = 5 // ECDSA cipher P-224 curve
	ECDSA256         Algorithm = 6 // ECDSA cipher P-256 curve
	ECDSA384         Algorithm = 7 // ECDSA cipher P-384 curve
	ECDSA521         Algorithm = 8 // ECDSA cipher P-521 curve
	ED25519          Algorithm = 9 // ED25519 cipher
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

const unknownAlgorithmNamePattern = "unknown algorithm name: '%s'"

// AlgorithmFromString determines an algorithm from its name.
func AlgorithmFromString(name string) (Algorithm, error) {
	switch name {
	case "RSA2048":
		return RSA2048, nil
	case "RSA3072":
		return RSA3072, nil
	case "RSA4096":
		return RSA4096, nil
	case "RSA8192":
		return RSA8192, nil
	case "ECDSA224":
		return ECDSA224, nil
	case "ECDSA256":
		return ECDSA256, nil
	case "ECDSA384":
		return ECDSA384, nil
	case "ECDSA521":
		return ECDSA521, nil
	case "ED25519":
		return ED25519, nil
	}
	return UnknownAlgorithm, fmt.Errorf(unknownAlgorithmNamePattern, name)
}

// AlgorithmFromKey determines the algorithm of the given public key.
func AlgorithmFromKey(publicKey crypto.PublicKey) (Algorithm, error) {
	rsaKey, ok := publicKey.(*rsa.PublicKey)
	if ok {
		return algorithmFromRSAKey(rsaKey)
	}
	ecdsaKey, ok := publicKey.(*ecdsa.PublicKey)
	if ok {
		return algorithmFromECDSAKey(ecdsaKey)
	}
	ed25519Key, ok := publicKey.(ed25519.PublicKey)
	if ok {
		return algorithmFromED25519Key(ed25519Key)
	}
	return UnknownAlgorithm, fmt.Errorf("unrecognized key type")
}

func algorithmFromRSAKey(publicKey *rsa.PublicKey) (Algorithm, error) {
	keySize := publicKey.Size()
	switch keySize {
	case 256:
		return RSA2048, nil
	case 384:
		return RSA3072, nil
	case 512:
		return RSA4096, nil
	case 1024:
		return RSA8192, nil
	}
	return UnknownAlgorithm, fmt.Errorf("unexpected RSA key size: %d", keySize)
}

func algorithmFromECDSAKey(publicKey *ecdsa.PublicKey) (Algorithm, error) {
	curveName := publicKey.Curve.Params().Name
	switch curveName {
	case "P-224":
		return ECDSA224, nil
	case "P-256":
		return ECDSA256, nil
	case "P-384":
		return ECDSA384, nil
	case "P-521":
		return ECDSA521, nil
	}
	return UnknownAlgorithm, fmt.Errorf("unexpected ECDSA key curve: '%s'", curveName)
}

func algorithmFromED25519Key(publicKey ed25519.PublicKey) (Algorithm, error) {
	return ED25519, nil
}

const unknownAlgorithmPattern = "unknown algorithm: %d"

// String gets the algorithm's name.
func (algorithm Algorithm) String() string {
	switch algorithm {
	case RSA2048:
		return "RSA2048"
	case RSA3072:
		return "RSA3072"
	case RSA4096:
		return "RSA4096"
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
	case UnknownAlgorithm:
		return "unknown"
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
