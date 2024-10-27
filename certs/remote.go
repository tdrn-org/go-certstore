// Copyright (C) 2023-2024 Holger de Carne and contributors
//
// This software may be modified and distributed under the terms
// of the MIT license.  See the LICENSE file for details.

package certs

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"fmt"

	"github.com/rs/zerolog"
	"github.com/tdrn-org/go-certstore/keys"
	"github.com/tdrn-org/go-log"
)

const remoteFactoryName = "Remote"

type remoteCertificateFactory struct {
	template *x509.Certificate
	request  *x509.CertificateRequest
	parent   *x509.Certificate
	signer   crypto.PrivateKey
	logger   *zerolog.Logger
}

func (factory *remoteCertificateFactory) Name() string {
	return remoteFactoryName
}

func (factory *remoteCertificateFactory) New() (crypto.PrivateKey, *x509.Certificate, error) {
	createTemplate := factory.template
	factory.logger.Info().Msg("creating X.509 certificate from remote request...")
	createTemplate.SerialNumber = nextSerialNumber()
	certificateBytes, err := x509.CreateCertificate(rand.Reader, createTemplate, factory.parent, factory.request.PublicKey, factory.signer)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate (cause: %w)", err)
	}
	certificate, err := x509.ParseCertificate(certificateBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed parse certificate bytes (cause: %w)", err)
	}
	return nil, certificate, nil
}

// NewRemoteCertificateFactory creates a new certificate factory for request based certificates.
func NewRemoteCertificateFactory(template *x509.Certificate, request *x509.CertificateRequest, parent *x509.Certificate, signer crypto.PrivateKey) CertificateFactory {
	logger := log.RootLogger().With().Str("Factory", remoteFactoryName).Logger()
	return &remoteCertificateFactory{
		template: template,
		request:  request,
		parent:   parent,
		signer:   signer,
		logger:   &logger,
	}
}

type remoteCertificateRequestFactory struct {
	template       *x509.CertificateRequest
	keyPairFactory keys.KeyPairFactory
	logger         *zerolog.Logger
}

func (factory *remoteCertificateRequestFactory) Name() string {
	return remoteFactoryName
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
	logger := log.RootLogger().With().Str("Factory", remoteFactoryName).Logger()
	return &remoteCertificateRequestFactory{
		template:       template,
		keyPairFactory: keyPairFactory,
		logger:         &logger,
	}
}
