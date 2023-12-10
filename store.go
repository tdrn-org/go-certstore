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
	"fmt"
	"strings"

	"github.com/hdecarne-github/go-certstore/certs"
	"github.com/hdecarne-github/go-certstore/storage"
	"github.com/hdecarne-github/go-log"
	"github.com/rs/zerolog"
)

type Audit int

const (
	AuditCreate Audit = 1
	AuditAccess Audit = 2
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
	return registry.createEntryData(name, data)
}

func (registry *Registry) CreateCertificateRequest(name string, factory certs.CertificateRequestFactory, user string) (string, error) {
	key, certificateRequest, err := factory.New()
	if err != nil {
		return "", err
	}
	data := &registryEntryData{}
	err = data.setKey(key, registry.settings.Secret)
	if err != nil {
		return "", err
	}
	data.setCertificateRequest(certificateRequest)
	return registry.createEntryData(name, data)
}

func (registry *Registry) Entries() (*RegistryEntries, error) {
	names, err := registry.backend.List()
	if err != nil {
		return nil, err
	}
	return &RegistryEntries{registry: registry, names: names}, nil
}

func (registry *Registry) Entry(name string) (*RegistryEntry, error) {
	data, err := registry.getEntryData(name)
	if err != nil {
		return nil, err
	}
	key, err := data.getKey(registry.settings.Secret)
	if err != nil {
		return nil, err
	}
	certificate, err := data.getCertificate()
	if err != nil {
		return nil, err
	}
	certificateRequest, err := data.getCertificateRequest()
	if err != nil {
		return nil, err
	}
	revocationList, err := data.getRevocationList()
	if err != nil {
		return nil, err
	}
	return &RegistryEntry{
		registry:           registry,
		name:               name,
		key:                key,
		certificate:        certificate,
		certificateRequest: certificateRequest,
		revocationList:     revocationList,
	}, nil
}

func (registry *Registry) isValidEntryName(name string) bool {
	return !strings.HasPrefix(name, ".")
}

func (registry *Registry) createEntryData(name string, data *registryEntryData) (string, error) {
	dataBytes, err := registry.marshalEntryData(data)
	if err != nil {
		return "", err
	}
	createdName, err := registry.backend.Create(name, dataBytes)
	if err != nil {
		return "", err
	}
	return createdName, nil
}

func (registry *Registry) updateEntryData(name string, data *registryEntryData) (storage.Version, error) {
	dataBytes, err := registry.marshalEntryData(data)
	if err != nil {
		return 0, err
	}
	version, err := registry.backend.Update(name, dataBytes)
	if err != nil {
		return 0, err
	}
	return version, nil
}

func (registry *Registry) marshalEntryData(data *registryEntryData) ([]byte, error) {
	dataBytes, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal entry data (cause: %w)", err)
	}
	return dataBytes, nil
}

func (registry *Registry) getEntryData(name string) (*registryEntryData, error) {
	dataBytes, err := registry.backend.Get(name)
	if err != nil {
		return nil, err
	}
	data, err := registry.unmarshalEntryData(dataBytes)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func (registry *Registry) unmarshalEntryData(dataBytes []byte) (*registryEntryData, error) {
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

type RegistryEntry struct {
	registry           *Registry
	name               string
	key                crypto.PrivateKey
	certificate        *x509.Certificate
	certificateRequest *x509.CertificateRequest
	revocationList     *x509.RevocationList
}

func (entry *RegistryEntry) Name() string {
	return entry.name
}

func (entry *RegistryEntry) IsRoot() bool {
	if entry.certificate == nil {
		return false
	}
	return certs.IsRoot(entry.certificate)
}

func (entry *RegistryEntry) CanIssue() bool {
	return entry.key != nil && entry.certificate != nil
}

func (entry *RegistryEntry) HasKey() bool {
	return entry.key != nil
}

func (entry *RegistryEntry) Key(user string) (crypto.PrivateKey, error) {
	if entry.key == nil {
		return entry.key, nil
	}
	return entry.key, nil
}

func (entry *RegistryEntry) HasCertificate() bool {
	return entry.certificate != nil
}

func (entry *RegistryEntry) Certificate() *x509.Certificate {
	return entry.certificate
}

func (entry *RegistryEntry) HasCertificateRequest() bool {
	return entry.certificateRequest != nil
}

func (entry *RegistryEntry) CertificateRequest() *x509.CertificateRequest {
	return entry.certificateRequest
}

func (entry *RegistryEntry) ResetRevocationList(factory certs.RevocationListFactory, user string) (*x509.RevocationList, error) {
	if !(entry.IsRoot() && entry.CanIssue()) {
		return nil, fmt.Errorf("cannot create revocation list for non-root/non-issueing certificate")
	}
	revocationList, err := factory.New()
	if err != nil {
		return nil, err
	}
	data, err := entry.registry.getEntryData(entry.name)
	if err != nil {
		return nil, err
	}
	data.setRevocationList(revocationList)
	entry.registry.updateEntryData(entry.name, data)
	entry.revocationList = revocationList
	return revocationList, nil
}

func (entry *RegistryEntry) HasRevocationList() bool {
	return entry.revocationList != nil
}

func (entry *RegistryEntry) RevocationList() *x509.RevocationList {
	return entry.revocationList
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
	if entryData.EncodedKey == "" {
		return nil, nil
	}
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
	if entryData.EncodedCertificate == "" {
		return nil, nil
	}
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

func (entryData *registryEntryData) setCertificateRequest(certificateRequest *x509.CertificateRequest) {
	entryData.EncodedCertificateRequest = base64.StdEncoding.EncodeToString(certificateRequest.Raw)
}

func (entryData *registryEntryData) getCertificateRequest() (*x509.CertificateRequest, error) {
	if entryData.EncodedCertificateRequest == "" {
		return nil, nil
	}
	certificateRequestData, err := base64.StdEncoding.DecodeString(entryData.EncodedCertificateRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to decode certificate request data (cause: %w)", err)
	}
	certificateRequest, err := x509.ParseCertificateRequest(certificateRequestData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate request data (cause: %w)", err)
	}
	return certificateRequest, nil
}

func (entryData *registryEntryData) setRevocationList(revocationList *x509.RevocationList) {
	entryData.EncodedRevocationList = base64.StdEncoding.EncodeToString(revocationList.Raw)
}

func (entryData *registryEntryData) getRevocationList() (*x509.RevocationList, error) {
	if entryData.EncodedRevocationList == "" {
		return nil, nil
	}
	revocationListData, err := base64.StdEncoding.DecodeString(entryData.EncodedRevocationList)
	if err != nil {
		return nil, fmt.Errorf("failed to decode revocation list data (cause: %w)", err)
	}
	revocationList, err := x509.ParseRevocationList(revocationListData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse revocation list data (cause: %w)", err)
	}
	return revocationList, nil
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
