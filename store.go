// Copyright (C) 2023 Holger de Carne and contributors
//
// This software may be modified and distributed under the terms
// of the MIT license.  See the LICENSE file for details.

// Package store provides functionality for creation and mantainenace of X.509 certificate stores.
package store

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/hdecarne-github/go-certstore/certs"
	"github.com/hdecarne-github/go-certstore/storage"
	"github.com/hdecarne-github/go-log"
	"github.com/rs/zerolog"
)

type AuditLog int

const (
	AuditCreate AuditLog = 1
	AuditAccess AuditLog = 2
)

type Registry struct {
	settings *storeSettings
	backend  storage.Backend
	logger   *zerolog.Logger
}

func (registry *Registry) Name() string {
	return fmt.Sprintf("Registry[%s]", registry.backend.URI())
}

func (registry *Registry) CreateCertificate(name string, factory certs.CertificateFactory, user string) (string, error) {
	key, certificate, err := factory.New()
	if err != nil {
		return "", err
	}
	data := &registryEntryData{}
	err = data.setKey(key, registry.settings.Secret)
	if err != nil {
		return "", err
	}
	data.setCertificate(certificate)
	dataBytes, err := registry.marshalEntry(data)
	if err != nil {
		return "", err
	}
	createdName, err := registry.backend.Create(name, dataBytes)
	if err != nil {
		return "", err
	}
	return createdName, nil
}

func (registry *Registry) Entries() (*RegistryEntries, error) {
	names, err := registry.backend.List()
	if err != nil {
		return nil, err
	}
	return &RegistryEntries{registry: registry, names: names}, nil
}

func (registry *Registry) Entry(name string) (*RegistryEntry, error) {
	dataBytes, err := registry.backend.Get(name)
	if err != nil {
		return nil, err
	}
	data, err := registry.unmarshalEntry(dataBytes)
	if err != nil {
		return nil, err
	}
	return &RegistryEntry{registry: registry, name: name, data: data}, nil
}

func (registry *Registry) isValidEntryName(name string) bool {
	return !strings.HasPrefix(name, ".")
}

func (registry *Registry) marshalEntry(data *registryEntryData) ([]byte, error) {
	dataBytes, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal entry data (cause: %w)", err)
	}
	return dataBytes, nil
}

func (registry *Registry) unmarshalEntry(dataBytes []byte) (*registryEntryData, error) {
	data := &registryEntryData{}
	err := json.Unmarshal(dataBytes, data)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal entry data (cause: %w)", err)
	}
	return data, nil
}

type RegistryEntries struct {
	registry *Registry
	names    storage.Names
}

func (entries *RegistryEntries) Next() (*RegistryEntry, error) {
	var name string
	for {
		name = entries.names.Next()
		if name == "" {
			return nil, nil
		}
		if entries.registry.isValidEntryName(name) {
			break
		}
	}
	return entries.registry.Entry(name)
}

var ErrNoKey = errors.New("key does not exist")

var ErrNoCertificate = errors.New("certificate does not exist")

type RegistryEntry struct {
	registry                  *Registry
	name                      string
	data                      *registryEntryData
	decodedKey                crypto.PrivateKey
	decodedCertificate        *x509.Certificate
	decodedCertificateRequest *x509.CertificateRequest
	decodedRevocationList     *x509.RevocationList
}

func (entry *RegistryEntry) Name() string {
	return entry.name
}

func (entry *RegistryEntry) HasKey() bool {
	return entry.data.EncodedKey != ""
}

func (entry *RegistryEntry) Key() (crypto.PrivateKey, error) {
	if entry.decodedKey != nil {
		return entry.decodedKey, nil
	}
	if !entry.HasKey() {
		return nil, ErrNoKey
	}
	key, err := entry.data.getKey(entry.registry.settings.Secret)
	if err != nil {
		return nil, err
	}
	entry.decodedKey = key
	return key, nil
}

func (entry *RegistryEntry) HasCertificate() bool {
	return entry.data.EncodedCertificate != ""
}

func (entry *RegistryEntry) Certificate() (*x509.Certificate, error) {
	if entry.decodedCertificate != nil {
		return entry.decodedCertificate, nil
	}
	if !entry.HasCertificate() {
		return nil, ErrNoCertificate
	}
	certificate, err := entry.data.getCertificate()
	if err != nil {
		return nil, err
	}
	entry.decodedCertificate = certificate
	return certificate, nil
}

type registryEntryData struct {
	EncodedKey                string            `json:"key"`
	EncodedCertificate        string            `json:"crt"`
	EncodedCertificateRequest string            `json:"csr"`
	EncodedRevocationList     string            `json:"crl"`
	Attributes                map[string]string `json:"attributes"`
}

func (entryData *registryEntryData) setKey(key crypto.PrivateKey, secret string) error {
	keyData, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("failed to marshal private key (cause: %w)", err)
	}
	encryptedKeyData, err := entryData.encryptData(keyData, secret)
	if err != nil {
		return fmt.Errorf("failed to encrypt private key (cause: %w)", err)
	}
	entryData.EncodedKey = base64.StdEncoding.EncodeToString(encryptedKeyData)
	return nil
}

func (entryData *registryEntryData) getKey(secret string) (crypto.PrivateKey, error) {
	encryptedKeyData, err := base64.StdEncoding.DecodeString(entryData.EncodedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode key data (cause: %w)", err)
	}
	keyData, err := entryData.decryptData(encryptedKeyData, secret)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt key data (cause: %w)", err)
	}
	key, err := x509.ParsePKCS8PrivateKey(keyData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse key data (cause: %w)", err)
	}
	return key, nil
}

func (entryData *registryEntryData) setCertificate(certificate *x509.Certificate) {
	entryData.EncodedCertificate = base64.StdEncoding.EncodeToString(certificate.Raw)
}

func (entryData *registryEntryData) getCertificate() (*x509.Certificate, error) {
	certificateData, err := base64.StdEncoding.DecodeString(entryData.EncodedCertificate)
	if err != nil {
		return nil, fmt.Errorf("failed to decode certificate data (cause: %w)", err)
	}
	certificate, err := x509.ParseCertificate(certificateData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate data (cause: %w)", err)
	}
	return certificate, nil
}

func (entryData *registryEntryData) encryptData(data []byte, secret string) ([]byte, error) {
	gcm, err := entryData.newGCM(secret)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	_, err = rand.Read(nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to generate nonce (cause: %w)", err)
	}
	encrypted, err := gcm.Seal(nonce, nonce, data, nil), nil
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt data (cause: %w)", err)
	}
	return encrypted, nil
}

func (entryData *registryEntryData) decryptData(data []byte, secret string) ([]byte, error) {
	gcm, err := entryData.newGCM(secret)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	nonce := data[:nonceSize]
	ciphertext := data[nonceSize:]
	decrypted, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data (cause: %w)", err)
	}
	return decrypted, nil
}

func (entryData *registryEntryData) newGCM(secret string) (cipher.AEAD, error) {
	secretBytes, err := base64.StdEncoding.DecodeString(secret)
	if err != nil {
		return nil, fmt.Errorf("failed to decode secret (cause: %w)", err)
	}
	aes, err := aes.NewCipher(secretBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher (cause: %w)", err)
	}
	gcm, err := cipher.NewGCM(aes)
	if err != nil {
		return nil, fmt.Errorf("failed to create block cipher (cause: %w)", err)
	}
	return gcm, nil
}

const storeSettingsName = ".store"

type storeSettings struct {
	Secret string `json:"secret"`
}

func NewStore(backend storage.Backend) (*Registry, error) {
	logger := log.RootLogger().With().Str("Registry", backend.URI()).Logger()
	settings, err := newStoreSettings(backend, &logger)
	if err != nil {
		return nil, err
	}
	return &Registry{
		settings: settings,
		backend:  backend,
		logger:   &logger,
	}, nil
}

func newStoreSettings(backend storage.Backend, logger *zerolog.Logger) (*storeSettings, error) {
	data, err := backend.Get(storeSettingsName)
	settings := &storeSettings{}
	if err == nil {
		err = json.Unmarshal(data, settings)
	} else if err == storage.ErrNotExist {
		err = initStoreSettings(backend, logger, settings)
	} else {
		return nil, fmt.Errorf("failed to read store settings '%s' (cause: %w)", storeSettingsName, err)
	}
	return settings, err
}

func initStoreSettings(backend storage.Backend, logger *zerolog.Logger, settings *storeSettings) error {
	logger.Info().Msg("initializing store settings...")
	secretBytes := make([]byte, 32)
	_, err := rand.Read(secretBytes)
	if err != nil {
		return fmt.Errorf("failed to generate random secret (cause: %w)", err)
	}
	settings.Secret = base64.StdEncoding.EncodeToString(secretBytes)
	data, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to encode store settings (cause: %w)", err)
	}
	_, err = backend.Create(storeSettingsName, data)
	return err
}
