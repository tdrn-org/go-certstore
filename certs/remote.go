// Copyright (C) 2023 Holger de Carne and contributors
//
// This software may be modified and distributed under the terms
// of the MIT license.  See the LICENSE file for details.

package certs

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"fmt"

	"github.com/hdecarne-github/go-certstore/keys"
	"github.com/hdecarne-github/go-log"
	"github.com/rs/zerolog"
)

const remoteCertificateRequestFactoryName = "Remote"

type remoteCertificateRequestFactory struct {
	template       *x509.CertificateRequest
	keyPairFactory keys.KeyPairFactory
	logger         *zerolog.Logger
}

func (factory *remoteCertificateRequestFactory) Name() string {
	return remoteCertificateRequestFactoryName
}

func (factory *remoteCertificateRequestFactory) New() (crypto.PrivateKey, *x509.CertificateRequest, error) {
	keyPair, err := factory.keyPairFactory.New()
	if err != nil {
		return nil, nil, err
	}
	factory.logger.Info().Msg("creating X.509 certificate request for remote signing...")
	certificateRequestBytes, err := x509.CreateCertificateRequest(rand.Reader, factory.template, keyPair.Private())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate request (cause: %w)", err)
	}
	certificateRequest, err := x509.ParseCertificateRequest(certificateRequestBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed parse certificate request bytes (cause: %w)", err)
	}
	return keyPair.Private(), certificateRequest, nil
}

// NewRemoteCertificateRequestFactory creates a new certificate request factory for remotely signed certificates.
func NewRemoteCertificateRequestFactory(template *x509.CertificateRequest, keyPairFactory keys.KeyPairFactory) CertificateRequestFactory {
	logger := log.RootLogger().With().Str("Factory", remoteCertificateRequestFactoryName).Logger()
	return &remoteCertificateRequestFactory{
		template:       template,
		keyPairFactory: keyPairFactory,
		logger:         &logger,
	}
}
