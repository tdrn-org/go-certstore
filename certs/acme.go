// Copyright (C) 2023 Holger de Carne and contributors
//
// This software may be modified and distributed under the terms
// of the MIT license.  See the LICENSE file for details.

package certs

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
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

const acmeCertficateFactoryNamePattern = "ACME[%s]"

type acmeCertificateFactory struct {
	name           string
	domains        []string
	config         *acme.Config
	providerName   string
	keyPairFactory keys.KeyPairFactory
	logger         *zerolog.Logger
}

func (factory *acmeCertificateFactory) Name() string {
	return factory.name
}

func (factory *acmeCertificateFactory) New() (crypto.PrivateKey, *x509.Certificate, error) {
	providerConfig, err := factory.config.ResolveProviderConfig(factory.providerName)
	if err != nil {
		return nil, nil, err
	}
	client, err := providerConfig.PrepareClient(factory.keyPairFactory)
	if err != nil {
		return nil, nil, err
	}
	domainConfig, err := factory.config.ResolveDomainConfig(factory.domains)
	if err != nil {
		return nil, nil, err
	}
	if domainConfig.Http01Challenge.Enabled {
		client.Challenge.SetHTTP01Provider(http01.NewProviderServer(domainConfig.Http01Challenge.Iface, strconv.Itoa(domainConfig.Http01Challenge.Port)))
	}
	if domainConfig.TLSAPN01Challenge.Enabled {
		client.Challenge.SetTLSALPN01Provider(tlsalpn01.NewProviderServer(domainConfig.TLSAPN01Challenge.Iface, strconv.Itoa(domainConfig.TLSAPN01Challenge.Port)))
	}
	key, err := factory.keyPairFactory.New()
	if err != nil {
		return nil, nil, err
	}
	request := certificate.ObtainRequest{
		Domains:    factory.domains,
		PrivateKey: key.Private(),
		Bundle:     false,
	}
	factory.logger.Info().Msg("obtaining X.509 certificate from ACME provider...")
	certificates, err := client.Certificate.Obtain(request)
	if err != nil {
		return nil, nil, err
	}
	obtainedKey, err := factory.decodePrivateKey(certificates.PrivateKey)
	if err != nil {
		return nil, nil, err
	}
	obtainedCertificate, err := factory.decodeCertificate(certificates.Certificate)
	if err != nil {
		return nil, nil, err
	}
	return obtainedKey, obtainedCertificate, nil
}

func (factory *acmeCertificateFactory) decodePrivateKey(keyBytes []byte) (crypto.PrivateKey, error) {
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

func (factory *acmeCertificateFactory) decodeCertificate(certificateBytes []byte) (*x509.Certificate, error) {
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

func NewACMECertificateFactory(domains []string, config *acme.Config, providerName string, keyPairFactory keys.KeyPairFactory) CertificateFactory {
	name := fmt.Sprintf(acmeCertficateFactoryNamePattern, providerName)
	logger := log.RootLogger().With().Str("Provider", name).Logger()
	return &acmeCertificateFactory{
		name:           name,
		domains:        domains,
		config:         config,
		providerName:   providerName,
		keyPairFactory: keyPairFactory,
		logger:         &logger,
	}
}
