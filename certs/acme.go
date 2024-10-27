// Copyright (C) 2023-2024 Holger de Carne and contributors
//
// This software may be modified and distributed under the terms
// of the MIT license.  See the LICENSE file for details.

package certs

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"strconv"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-acme/lego/v4/challenge/tlsalpn01"
	"github.com/hdecarne-github/go-certstore/certs/acme"
	"github.com/hdecarne-github/go-certstore/keys"
	"github.com/hdecarne-github/go-log"
	"github.com/rs/zerolog"
)

const acmeFactoryNamePattern = "ACME[%s]"

type acmeCertificateFactory struct {
	name               string
	certificateRequest *acme.CertificateRequest
	keyPairFactory     keys.KeyPairFactory
	logger             *zerolog.Logger
}

func (factory *acmeCertificateFactory) Name() string {
	return factory.name
}

func (factory *acmeCertificateFactory) New() (crypto.PrivateKey, *x509.Certificate, error) {
	client, err := factory.certificateRequest.Provider.NewClient(factory.keyPairFactory)
	if err != nil {
		return nil, nil, err
	}
	if factory.certificateRequest.Domain.Http01Challenge.Enabled {
		client.Challenge.SetHTTP01Provider(http01.NewProviderServer(factory.certificateRequest.Domain.Http01Challenge.Iface, strconv.Itoa(factory.certificateRequest.Domain.Http01Challenge.Port)))
	}
	if factory.certificateRequest.Domain.TLSALPN01Challenge.Enabled {
		client.Challenge.SetTLSALPN01Provider(tlsalpn01.NewProviderServer(factory.certificateRequest.Domain.TLSALPN01Challenge.Iface, strconv.Itoa(factory.certificateRequest.Domain.TLSALPN01Challenge.Port)))
	}
	key, err := factory.keyPairFactory.New()
	if err != nil {
		return nil, nil, err
	}
	request := certificate.ObtainRequest{
		Domains:    factory.certificateRequest.Domains,
		PrivateKey: key.Private(),
		Bundle:     false,
	}
	factory.logger.Info().Msgf("obtaining X.509 certificate from ACME provider '%s...", factory.certificateRequest.Provider.Name)
	certificates, err := client.Certificate.Obtain(request)
	if err != nil {
		return nil, nil, err
	}
	obtainedKey, obtainedCertificate, err := acme.DecodeCertificates(certificates)
	if err != nil {
		return nil, nil, err
	}
	return obtainedKey, obtainedCertificate, nil
}

// NewACMECertificateFactory creates a new certificate factory for ACME based certificates.
func NewACMECertificateFactory(certificateRequest *acme.CertificateRequest, keyPairFactory keys.KeyPairFactory) CertificateFactory {
	name := fmt.Sprintf(acmeFactoryNamePattern, certificateRequest.Provider.Name)
	logger := log.RootLogger().With().Str("Factory", name).Logger()
	return &acmeCertificateFactory{
		name:               name,
		certificateRequest: certificateRequest,
		keyPairFactory:     keyPairFactory,
		logger:             &logger,
	}
}
