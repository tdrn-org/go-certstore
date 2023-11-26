// Copyright (C) 2023 Holger de Carne and contributors
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

type Config struct {
	BasePath  string                    `yaml:"-"`
	Providers map[string]ProviderConfig `yaml:"providers"`
	Domains   map[string]DomainConfig   `yaml:"domains"`
}

func (config *Config) ResolveProviderConfig(providerName string) (*ProviderConfig, error) {
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
	return providerConfig, nil
}

func (config *Config) ResolveDomainConfig(domains []string) (*DomainConfig, error) {
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
	return domainConfig, nil
}

type ProviderConfig struct {
	BasePath          string `yaml:"-"`
	Name              string `yaml:"-"`
	URL               string `yaml:"url"`
	RegistrationEmail string `yaml:"registration_email"`
	RegistrationPath  string `yaml:"registration_path"`
}

func (providerConfig *ProviderConfig) PrepareClient(keyPairFactory keys.KeyPairFactory) (*lego.Client, error) {
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
	return providerConfig.prepareClientHelper(registrationFile, keyPairFactory)
}

func (providerConfig *ProviderConfig) absoluteRegistrationPath() string {
	absoluteRegistrationPath := providerConfig.RegistrationPath
	if !filepath.IsAbs(absoluteRegistrationPath) {
		absoluteRegistrationPath = filepath.Join(providerConfig.BasePath, absoluteRegistrationPath)
	}
	return absoluteRegistrationPath
}

func (providerConfig *ProviderConfig) prepareClientHelper(registrationFile *os.File, keyPairFactory keys.KeyPairFactory) (*lego.Client, error) {
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
		err = registration.register(client, keyPairFactory)
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
	kpfName := keyPairFactory.Name()
	switch kpfName {
	case "ECDSA P-256":
		return certcrypto.EC256, nil
	case "ECDSA P-384":
		return certcrypto.EC384, nil
	case "RSA 2048":
		return certcrypto.RSA2048, nil
	case "RSA 4096":
		return certcrypto.RSA4096, nil
	case "RSA 8192":
		return certcrypto.RSA8192, nil
	}
	return "", fmt.Errorf("unrecognized key type '%s'", kpfName)
}

type DomainConfig struct {
	Domain            string                  `yaml:"-"`
	Http01Challenge   Http01ChallengeConfig   `yaml:"http-01"`
	TLSAPN01Challenge TLSAPN01ChallengeConfig `yaml:"tls-apn-01"`
}

type Http01ChallengeConfig struct {
	Enabled bool   `yaml:"enabled"`
	Iface   string `yaml:"iface"`
	Port    int    `ymal:"port"`
}

type TLSAPN01ChallengeConfig struct {
	Enabled bool   `yaml:"enabled"`
	Iface   string `yaml:"iface"`
	Port    int    `ymal:"port"`
}

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
