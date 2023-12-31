// Copyright (C) 2023-2024 Holger de Carne and contributors
//
// This software may be modified and distributed under the terms
// of the MIT license.  See the LICENSE file for details.

// Package acme provides [LEGO] related utility functions.
//
// [LEGO]:https://pkg.go.dev/github.com/go-acme/lego/v4
package acme

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/go-acme/lego/v4/certificate"
	legolog "github.com/go-acme/lego/v4/log"
	"github.com/hdecarne-github/go-log"
	"github.com/rs/zerolog"
)

// DecodeCertificates decodes the certificate information (private key and certificate) as returned by the [LEGO client].
//
// [LEGO client]:https://pkg.go.dev/github.com/go-acme/lego/v4
func DecodeCertificates(resource *certificate.Resource) (crypto.PrivateKey, *x509.Certificate, error) {
	key, err := DecodePrivateKey(resource.PrivateKey)
	if err != nil {
		return nil, nil, err
	}
	certificate, err := DecodeCertificate(resource.Certificate)
	if err != nil {
		return nil, nil, err
	}
	return key, certificate, nil
}

// DecodePrivateKey decodes the private key as returned by the [LEGO client].
//
// [LEGO client]:https://pkg.go.dev/github.com/go-acme/lego/v4
func DecodePrivateKey(keyBytes []byte) (crypto.PrivateKey, error) {
	pemBlock, rest := pem.Decode(keyBytes)
	if pemBlock == nil {
		return nil, fmt.Errorf("failed to decode key")
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("unexpected trailing bytes in key")
	}
	var key crypto.PrivateKey
	switch pemBlock.Type {
	case "EC PRIVATE KEY":
		ecKey, err := x509.ParseECPrivateKey(pemBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse EC key (cause: %w)", err)
		}
		key = ecKey
	case "RSA PRIVATE KEY":
		rsaKey, err := x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse RSA key (cause: %w)", err)
		}
		key = rsaKey
	default:
		return nil, fmt.Errorf("unexpected PEM block type '%s'", pemBlock.Type)
	}
	return key, nil
}

// DecodeCertificate decodes the certificate as returned by the [LEGO client].
//
// [LEGO client]:https://pkg.go.dev/github.com/go-acme/lego/v4
func DecodeCertificate(certificateBytes []byte) (*x509.Certificate, error) {
	pemBlock, rest := pem.Decode(certificateBytes)
	if pemBlock == nil {
		return nil, fmt.Errorf("failed to decode certificate")
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("unexpected trailing bytes in certificate")
	}
	certificate, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate (cause: %w)", err)
	}
	return certificate, nil
}

type legoLogger struct {
	logger *zerolog.Logger
}

func (lego *legoLogger) Fatal(args ...interface{}) {
	lego.logger.Fatal().Msg(fmt.Sprint(args...))
}

func (lego *legoLogger) Fatalln(args ...interface{}) {
	lego.logger.Fatal().Msg(fmt.Sprintln(args...))
}

func (lego *legoLogger) Fatalf(format string, args ...interface{}) {
	lego.logger.Fatal().Msg(fmt.Sprintf(format, args...))
}

func (lego *legoLogger) Print(args ...interface{}) {
	lego.logger.Info().Msg(fmt.Sprint(args...))
}

func (lego *legoLogger) Println(args ...interface{}) {
	lego.logger.Info().Msg(fmt.Sprintln(args...))
}

func (lego *legoLogger) Printf(format string, args ...interface{}) {
	lego.logger.Info().Msg(fmt.Sprintf(format, args...))
}

func init() {
	logger := log.RootLogger().With().Str("Log", "ACME").Logger()
	legolog.Logger = &legoLogger{
		logger: &logger,
	}
}
