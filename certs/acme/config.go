// Copyright (C) 2023-2024 Holger de Carne and contributors
//
// This software may be modified and distributed under the terms
// of the MIT license.  See the LICENSE file for details.

package acme

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/lego"
	"github.com/hdecarne-github/go-certstore/keys"
	"gopkg.in/yaml.v3"
)

// A Config defines the available ACME providers as well as the obtainable domains including their challenge types.
//
//	providers:
//	  "Test1":
//	    enabled: true
//	    url: "https://localhost:14000/dir"
//	    registration_email: "webmaster@localhost"
//	    registration_path: "./acme-registrations.json"
//
//	domains:
//	  ".":
//	    http-01:
//	      enabled: true
//	      iface: ""
//	      port: 5002
//	    tls-alpn-01:
//	      enabled: true
//	      iface: ""
//	      port: 5001
type Config struct {
	// BasePath defines the base path to use for resolving relative paths within this configuration.
	BasePath string `yaml:"-"`
	// Providers lists the available ACME providers in this configuration.
	Providers map[string]ProviderConfig `yaml:"providers"`
	// Domains lists the obtainable domains in this configuration.
	Domains map[string]DomainConfig `yaml:"domains"`
}

// A CertificateRequest provides the necessary ACME parameters for obtaining a certificate.
type CertificateRequest struct {
	Domains  []string
	Domain   *DomainConfig
	Provider *ProviderConfig
}

// ResolveCertificateRequest resolves the certificate request configured for the given domains and provider.
func (config *Config) ResolveCertificateRequest(domains []string, providerName string) (*CertificateRequest, error) {
	if len(domains) == 0 {
		return nil, fmt.Errorf("missing domain information")
	}
	domain := domains[0] + "."
	var domainConfig *DomainConfig
	for _, configDomainConfig := range config.Domains {
		if strings.HasSuffix(domain, configDomainConfig.Domain) {
			if domainConfig == nil || len(domainConfig.Domain) < len(configDomainConfig.Domain) {
				domainConfig = &configDomainConfig
			}
		}
	}
	if domainConfig == nil {
		return nil, fmt.Errorf("missing Domain configuration for domain '%s'", domain)
	}
	var providerConfig *ProviderConfig
	for _, configProvider := range config.Providers {
		if configProvider.Name == providerName {
			providerConfig = &configProvider
			break
		}
	}
	if providerConfig == nil {
		return nil, fmt.Errorf("unknown ACME provider '%s'", providerName)
	}
	return &CertificateRequest{
		Domains:  domains,
		Domain:   domainConfig,
		Provider: providerConfig,
	}, nil
}

// A ProviderConfig defines an ACME provider.
type ProviderConfig struct {
	// BasePath defines the base path to use for resolving relative paths within this configuration.
	BasePath string `yaml:"-"`
	// Name defines the name of this provider.
	Name string `yaml:"-"`
	// Enabled defines wether this provider is enabled (true) or not (false).
	Enabled bool `yaml:"enabled"`
	// URL defines the URL to use for accessing this provider.
	URL string `yaml:"url"`
	// RegistrationEmail defines the email to use for registering with this provider.
	RegistrationEmail string `yaml:"registration_email"`
	// RegistrationPath defines the path where to store the registration information.
	RegistrationPath string `yaml:"registration_path"`
}

// NewClient creates a new [lego.Client] based on the provider configuration. A necessary provider registration is performed automatically.
func (providerConfig *ProviderConfig) NewClient(keyPairFactory keys.KeyPairFactory) (*lego.Client, error) {
	absoluteRegistrationPath := providerConfig.absoluteRegistrationPath()
	err := os.MkdirAll(filepath.Dir(absoluteRegistrationPath), 0700)
	if err != nil {
		return nil, fmt.Errorf("failed to access registration file path '%s' (cause: %w)", absoluteRegistrationPath, err)
	}
	registrationFile, err := os.OpenFile(absoluteRegistrationPath, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to open registration file '%s' (cause: %w)", absoluteRegistrationPath, err)
	}
	defer registrationFile.Close()
	err = syscall.Flock(int(registrationFile.Fd()), syscall.LOCK_EX)
	if err != nil {
		return nil, fmt.Errorf("failed to lock registration file '%s' (cause: %w)", absoluteRegistrationPath, err)
	}
	defer syscall.Flock(int(registrationFile.Fd()), syscall.LOCK_UN)
	return providerConfig.newClientHelper(registrationFile, keyPairFactory)
}

func (providerConfig *ProviderConfig) absoluteRegistrationPath() string {
	absoluteRegistrationPath := providerConfig.RegistrationPath
	if !filepath.IsAbs(absoluteRegistrationPath) {
		absoluteRegistrationPath = filepath.Join(providerConfig.BasePath, absoluteRegistrationPath)
	}
	return absoluteRegistrationPath
}

func (providerConfig *ProviderConfig) newClientHelper(registrationFile *os.File, keyPairFactory keys.KeyPairFactory) (*lego.Client, error) {
	registration, err := prepareProviderRegistration(providerConfig, registrationFile, keyPairFactory)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare ACME provider registration for provder '%s' (cause: %w)", providerConfig.Name, err)
	}
	config := lego.NewConfig(registration)
	config.CADirURL = providerConfig.URL
	config.Certificate.KeyType, err = providerConfig.keyTypeFromKeyPairFactory(keyPairFactory)
	if err != nil {
		return nil, err
	}
	client, err := lego.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create client for provider '%s' (cause: %w)", providerConfig.Name, err)
	}
	if !registration.isActive(client) {
		err = registration.register(client)
		if err != nil {
			return nil, fmt.Errorf("failed to register client for provider '%s' (cause: %w)", providerConfig.Name, err)
		}
		err = registration.updateProviderRegistrations(registrationFile)
		if err != nil {
			return nil, fmt.Errorf("failed to update registration for provider '%s' (cause: %w)", providerConfig.Name, err)
		}
	}
	return client, nil
}

func (providerConfig *ProviderConfig) keyTypeFromKeyPairFactory(keyPairFactory keys.KeyPairFactory) (certcrypto.KeyType, error) {
	alg := keyPairFactory.Alg()
	switch alg {
	case keys.RSA2048:
		return certcrypto.RSA2048, nil
	case keys.RSA4096:
		return certcrypto.RSA4096, nil
	case keys.RSA8192:
		return certcrypto.RSA8192, nil
	case keys.ECDSA256:
		return certcrypto.EC256, nil
	case keys.ECDSA384:
		return certcrypto.EC384, nil
	}
	return "", fmt.Errorf("unrecognized key algorithm '%s'", alg)
}

// A DomainConfig defines a domain pattern as well as the challenge types for the matching domains.
type DomainConfig struct {
	// Domain defines the domain pattern, this config is assigned to. The pattern defines the suffix for the matching domains in FQDN notation ('.' defining the root domain matchin all domains).
	Domain string `yaml:"-"`
	// Http01Challenge configures the HTTP-01 challenge type.
	Http01Challenge Http01ChallengeConfig `yaml:"http-01"`
	// Http01Challenge configures the TLS-ALPN-01 challenge type.
	TLSALPN01Challenge TLSALPN01ChallengeConfig `yaml:"tls-alpn-01"`
}

// A Http01ChallengeConfig configures the HTTP-01 challenge type for domain validation.
type Http01ChallengeConfig struct {
	// Enabled defines wether this challenge type is enabled (true) or not (false).
	Enabled bool `yaml:"enabled"`
	// Iface sets the interface to listen on during domain verification (optional).
	Iface string `yaml:"iface"`
	// Ports sets the port to listen on during domain verification.
	Port int `ymal:"port"`
}

type TLSALPN01ChallengeConfig struct {
	// Enabled defines wether this challenge type is used (true) or not (false).
	Enabled bool `yaml:"enabled"`
	// Iface sets the interface to listen on during domain verification (optional).
	Iface string `yaml:"iface"`
	// Ports sets the port to listen on during domain verification.
	Port int `ymal:"port"`
}

// LoadConfig loads a configuration from the given file.
func LoadConfig(path string) (*Config, error) {
	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("failed to determine absolute path for configuration file '%s' (cause: %w)", path, err)
	}
	configBytes, err := os.ReadFile(absolutePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read configuration file '%s' (cause: %w)", path, err)
	}
	config := defaultConfig()
	err = yaml.Unmarshal(configBytes, config)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal configuration file '%s' (cause: %w)", path, err)
	}
	config.BasePath = filepath.Dir(absolutePath)
	for name, provider := range config.Providers {
		provider.BasePath = config.BasePath
		provider.Name = name
		config.Providers[name] = provider
	}
	for domain, domainConfig := range config.Domains {
		domainConfig.Domain = domain
		config.Domains[domain] = domainConfig
	}
	return config, nil
}

func defaultConfig() *Config {
	return &Config{
		Providers: make(map[string]ProviderConfig, 0),
		Domains:   make(map[string]DomainConfig, 0),
	}
}
