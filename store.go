// Copyright (C) 2023 Holger de Carne and contributors
//
// This software may be modified and distributed under the terms
// of the MIT license.  See the LICENSE file for details.

// Package store provides functionality for creation and mantainenace of X.509 certificate stores.
package store

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"maps"
	"runtime"
	"strings"
	"time"

	"github.com/hdecarne-github/go-certstore/certs"
	"github.com/hdecarne-github/go-certstore/keys"
	"github.com/hdecarne-github/go-certstore/storage"
	"github.com/hdecarne-github/go-log"
	"github.com/jellydator/ttlcache/v3"
	"github.com/rs/zerolog"
)

type Registry struct {
	settings   *storeSettings
	backend    storage.Backend
	entryCache *ttlcache.Cache[string, *RegistryEntry]
	logger     *zerolog.Logger
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
	if key != nil {
		err = data.setKey(key, registry.settings.Secret)
		if err != nil {
			return "", err
		}
	}
	data.setCertificate(certificate)
	createdName, err := registry.createEntryData(name, data)
	if err == nil {
		registry.audit(auditCreateCertificate, createdName, user)
	}
	return createdName, err
}

func (registry *Registry) MergeCertificate(name string, certificate *x509.Certificate, user string) (string, bool, error) {
	entries, err := registry.Entries()
	if err != nil {
		return "", false, err
	}
	entry, err := entries.Find(func(entry *RegistryEntry) bool { return entry.matchCertificate(certificate) })
	if err != nil {
		return "", false, err
	}
	var mergedName string
	var merged bool
	if entry != nil {
		mergedName = entry.Name()
		merged = !entry.HasCertificate()
		if merged {
			err = entry.mergeCertificate(certificate)
			if err != nil {
				return "", false, err
			}
		}
	} else {
		data := &registryEntryData{}
		data.setCertificate(certificate)
		mergedName, err = registry.createEntryData(name, data)
		if err != nil {
			return "", false, err
		}
	}
	if merged {
		if registry.entryCache != nil {
			registry.entryCache.Delete(mergedName)
		}
		registry.audit(auditMergeCertificate, mergedName, user)
	}
	return mergedName, merged, nil
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
	createdName, err := registry.createEntryData(name, data)
	if err == nil {
		registry.audit(auditCreateCertificateRequest, createdName, user)
	}
	return createdName, err
}

func (registry *Registry) MergeCertificateRequest(name string, certificateRequest *x509.CertificateRequest, user string) (string, bool, error) {
	entries, err := registry.Entries()
	if err != nil {
		return "", false, err
	}
	entry, err := entries.Find(func(entry *RegistryEntry) bool { return entry.matchCertificateRequest(certificateRequest) })
	if err != nil {
		return "", false, err
	}
	var mergedName string
	var merged bool
	if entry != nil {
		mergedName = entry.Name()
		merged = !entry.HasCertificateRequest()
		if merged {
			err = entry.mergeCertificateRequest(certificateRequest)
			if err != nil {
				return "", false, err
			}
		}
	} else {
		data := &registryEntryData{}
		data.setCertificateRequest(certificateRequest)
		mergedName, err = registry.createEntryData(name, data)
		if err != nil {
			return "", false, err
		}
	}
	if merged {
		if registry.entryCache != nil {
			registry.entryCache.Delete(mergedName)
		}
		registry.audit(auditMergeCertificateRequest, mergedName, user)
	}
	return mergedName, merged, nil
}

func (registry *Registry) MergeKey(name string, key crypto.PrivateKey, user string) (string, bool, error) {
	entries, err := registry.Entries()
	if err != nil {
		return "", false, err
	}
	entry, err := entries.Find(func(entry *RegistryEntry) bool { return entry.matchKey(key) })
	if err != nil {
		return "", false, err
	}
	var mergedName string
	var merged bool
	if entry != nil {
		mergedName = entry.Name()
		merged = !entry.HasCertificateRequest()
		if merged {
			err = entry.mergeKey(key)
			if err != nil {
				return "", false, err
			}
		}
	} else {
		data := &registryEntryData{}
		data.setKey(key, registry.settings.Secret)
		mergedName, err = registry.createEntryData(name, data)
		if err != nil {
			return "", false, err
		}
	}
	if merged {
		if registry.entryCache != nil {
			registry.entryCache.Delete(mergedName)
		}
		registry.audit(auditMergeKey, mergedName, user)
	}
	return mergedName, merged, nil
}

func (registry *Registry) MergeRevocationList(name string, revocationList *x509.RevocationList, user string) (string, bool, error) {
	entries, err := registry.Entries()
	if err != nil {
		return "", false, err
	}
	entry, err := entries.Find(func(entry *RegistryEntry) bool { return entry.matchRevocationList(revocationList) })
	if err != nil {
		return "", false, err
	}
	var mergedName string
	var merged bool
	if entry != nil {
		mergedName = entry.Name()
		merged = !entry.HasRevocationList()
		if merged {
			err = entry.mergeRevocationList(revocationList)
			if err != nil {
				return "", false, err
			}
		}
	} else {
		data := &registryEntryData{}
		data.setRevocationList(revocationList)
		mergedName, err = registry.createEntryData(name, data)
		if err != nil {
			return "", false, err
		}
	}
	if merged {
		if registry.entryCache != nil {
			registry.entryCache.Delete(mergedName)
		}
		registry.audit(auditMergeRevocationList, mergedName, user)
	}
	return mergedName, merged, nil
}

func (registry *Registry) Merge(other *Registry, user string) error {
	otherEntries, err := other.Entries()
	if err != nil {
		return err
	}
	for {
		otherEntry, err := otherEntries.Next()
		if err != nil {
			return err
		}
		if otherEntry == nil {
			break
		}
		err = registry.mergeEntry(otherEntry, user)
		if err != nil {
			return err
		}
	}
	return nil
}

func (registry *Registry) mergeEntry(entry *RegistryEntry, user string) error {
	if entry.HasCertificate() {
		_, _, err := registry.MergeCertificate("Imported certificate", entry.Certificate(), user)
		if err != nil {
			return err
		}
	}
	if entry.HasCertificateRequest() {
		_, _, err := registry.MergeCertificateRequest("Imported certificate request", entry.CertificateRequest(), user)
		if err != nil {
			return err
		}
	}
	if entry.HasKey() {
		_, _, err := registry.MergeKey("Imported key", entry.Key(user), user)
		if err != nil {
			return err
		}
	}
	if entry.HasRevocationList() {
		_, _, err := registry.MergeRevocationList("Imported revocation list", entry.RevocationList(), user)
		if err != nil {
			return err
		}
	}
	return nil
}

func (registry *Registry) Entries() (*RegistryEntries, error) {
	names, err := registry.backend.List()
	if err != nil {
		return nil, err
	}
	return &RegistryEntries{registry: registry, names: names}, nil
}

func (registry *Registry) Entry(name string) (*RegistryEntry, error) {
	if registry.entryCache != nil {
		cached := registry.entryCache.Get(name)
		if cached != nil {
			return cached.Value(), nil
		}
	}
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
	entry := &RegistryEntry{
		registry:           registry,
		name:               name,
		key:                key,
		certificate:        certificate,
		certificateRequest: certificateRequest,
		revocationList:     revocationList,
	}
	if registry.entryCache != nil {
		registry.entryCache.Set(name, entry, ttlcache.DefaultTTL)
	}
	return entry, nil
}

func (registry *Registry) CertPools() (*x509.CertPool, *x509.CertPool, error) {
	roots := x509.NewCertPool()
	intermediates := x509.NewCertPool()
	entries, err := registry.Entries()
	if err != nil {
		return nil, nil, err
	}
	for {
		entry, err := entries.Next()
		if err != nil {
			return nil, nil, err
		}
		if entry == nil {
			break
		}
		if entry.IsCA() {
			if entry.IsRoot() {
				roots.AddCert(entry.Certificate())
			} else {
				intermediates.AddCert(entry.Certificate())
			}
		}
	}
	return roots, intermediates, nil
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
	data := &registryEntryData{Attributes: make(map[string]string, 0)}
	err := json.Unmarshal(dataBytes, data)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal entry data (cause: %w)", err)
	}
	return data, nil
}

const storeAuditName = ".audit"

func (registry *Registry) audit(pattern auditPattern, name string, user string) {
	message := pattern.sprintf(name, user)
	registry.logger.Info().Msgf("audit: %s", message)
	err := registry.backend.Log(storeAuditName, message)
	if err != nil {
		registry.logger.Fatal().Err(err).Msgf("failed to write audit log '%s'", message)
	}
}

type auditPattern string

const (
	auditCreateCertificate        auditPattern = "%d;Create;Certificate;%s;%s"
	auditCreateCertificateRequest auditPattern = "%d;Create;CertificateRequest;%s;%s"
	auditCreateRevocationList     auditPattern = "%d;Create;RevocationList;%s;%s"
	auditAccessKey                auditPattern = "%d;Access;Key;%s;%s"
	auditMergeCertificate         auditPattern = "%d;Merge;Certificate;%s;%s"
	auditMergeCertificateRequest  auditPattern = "%d;Merge;CertificateRequest;%s;%s"
	auditMergeKey                 auditPattern = "%d;Merge;Key;%s;%s"
	auditMergeRevocationList      auditPattern = "%d;Merge;RevocationList;%s;%s"
)

func (pattern auditPattern) sprintf(name string, user string) string {
	return fmt.Sprintf(string(pattern), time.Now().UnixMilli(), name, user)
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

func (entries *RegistryEntries) Find(match func(entry *RegistryEntry) bool) (*RegistryEntry, error) {
	entry, err := entries.Next()
	for {
		if err != nil {
			return nil, err
		}
		if entry == nil || match(entry) {
			break
		}
		entry, err = entries.Next()
	}
	return entry, nil
}

type RegistryEntry struct {
	registry           *Registry
	name               string
	key                crypto.PrivateKey
	certificate        *x509.Certificate
	certificateRequest *x509.CertificateRequest
	revocationList     *x509.RevocationList
	attributes         map[string]string
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

func (entry *RegistryEntry) IsCA() bool {
	if entry.certificate == nil {
		return false
	}
	return entry.certificate.IsCA
}

func (entry *RegistryEntry) CanIssue(keyUsage x509.KeyUsage) bool {
	return entry.key != nil && entry.certificate != nil && (entry.certificate.KeyUsage&keyUsage) == keyUsage
}

func (entry *RegistryEntry) HasKey() bool {
	return entry.key != nil
}

func (entry *RegistryEntry) Key(user string) crypto.PrivateKey {
	if entry.key != nil {
		entry.registry.audit(auditAccessKey, entry.name, user)
	}
	return entry.key
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
	if !entry.CanIssue(x509.KeyUsageCRLSign) {
		return nil, fmt.Errorf("cannot create revocation list for selected certificate")
	}
	revocationList, err := factory.New(entry.Certificate(), entry.Key(user))
	if err != nil {
		return nil, err
	}
	err = entry.mergeRevocationList(revocationList)
	if err != nil {
		return nil, err
	}
	entry.registry.audit(auditCreateRevocationList, entry.name, user)
	return revocationList, nil
}

func (entry *RegistryEntry) HasRevocationList() bool {
	return entry.revocationList != nil
}

func (entry *RegistryEntry) RevocationList() *x509.RevocationList {
	return entry.revocationList
}

func (entry *RegistryEntry) Attributes() map[string]string {
	return maps.Clone(entry.attributes)
}

func (entry *RegistryEntry) SetAttributes(attributes map[string]string) error {
	err := entry.mergeAttributes(attributes)
	if err != nil {
		return err
	}
	return nil
}

func (entry *RegistryEntry) matchCertificate(certificate *x509.Certificate) bool {
	if entry.HasCertificate() {
		return bytes.Equal(entry.certificate.Raw, certificate.Raw)
	}
	if entry.HasKey() {
		return keys.PublicsEqual(keys.PublicFromPrivate(entry.key), certificate.PublicKey)
	}
	return false
}

func (entry *RegistryEntry) mergeCertificate(certificate *x509.Certificate) error {
	data, err := entry.registry.getEntryData(entry.name)
	if err != nil {
		return err
	}
	data.setCertificate(certificate)
	entry.registry.updateEntryData(entry.name, data)
	entry.certificate = certificate
	return nil
}

func (entry *RegistryEntry) matchCertificateRequest(certificateRequest *x509.CertificateRequest) bool {
	if entry.HasCertificateRequest() {
		return bytes.Equal(entry.certificateRequest.Raw, certificateRequest.Raw)
	}
	if entry.HasKey() {
		return keys.PublicsEqual(keys.PublicFromPrivate(entry.key), certificateRequest.PublicKey)
	}
	return false
}

func (entry *RegistryEntry) mergeCertificateRequest(certificateRequest *x509.CertificateRequest) error {
	data, err := entry.registry.getEntryData(entry.name)
	if err != nil {
		return err
	}
	data.setCertificateRequest(certificateRequest)
	entry.registry.updateEntryData(entry.name, data)
	entry.certificateRequest = certificateRequest
	return nil
}

func (entry *RegistryEntry) matchKey(key crypto.PrivateKey) bool {
	if entry.HasKey() {
		return keys.PrivatesEqual(entry.key, key)
	}
	if entry.HasCertificate() {
		return keys.PublicsEqual(entry.certificate.PublicKey, keys.PublicFromPrivate(key))
	}
	if entry.HasCertificateRequest() {
		return keys.PublicsEqual(entry.certificateRequest.PublicKey, keys.PublicFromPrivate(key))
	}
	return false
}

func (entry *RegistryEntry) mergeKey(key crypto.PrivateKey) error {
	data, err := entry.registry.getEntryData(entry.name)
	if err != nil {
		return err
	}
	data.setKey(key, entry.registry.settings.Secret)
	entry.registry.updateEntryData(entry.name, data)
	entry.key = key
	return nil
}

func (entry *RegistryEntry) matchRevocationList(revocationList *x509.RevocationList) bool {
	if entry.HasRevocationList() {
		return bytes.Equal(entry.revocationList.Raw, revocationList.Raw)
	}
	if entry.HasCertificate() {
		return revocationList.CheckSignatureFrom(entry.certificate) == nil
	}
	return false
}

func (entry *RegistryEntry) mergeRevocationList(revocationList *x509.RevocationList) error {
	data, err := entry.registry.getEntryData(entry.name)
	if err != nil {
		return err
	}
	data.setRevocationList(revocationList)
	entry.registry.updateEntryData(entry.name, data)
	entry.revocationList = revocationList
	return nil
}

func (entry *RegistryEntry) mergeAttributes(attributes map[string]string) error {
	data, err := entry.registry.getEntryData(entry.name)
	if err != nil {
		return err
	}
	data.Attributes = maps.Clone(attributes)
	entry.registry.updateEntryData(entry.name, data)
	entry.attributes = data.Attributes
	return nil
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

func NewStore(backend storage.Backend, cacheTTL time.Duration) (*Registry, error) {
	logger := log.RootLogger().With().Str("Registry", backend.URI()).Logger()
	settings, err := newStoreSettings(backend, &logger)
	if err != nil {
		return nil, err
	}
	var entryCache *ttlcache.Cache[string, *RegistryEntry]
	if cacheTTL > 0 {
		entryCache = ttlcache.New[string, *RegistryEntry](ttlcache.WithTTL[string, *RegistryEntry](cacheTTL))
		go entryCache.Start()
		runtime.SetFinalizer(entryCache, func(cache *ttlcache.Cache[string, *RegistryEntry]) { cache.Stop() })
	}
	return &Registry{
		settings:   settings,
		backend:    backend,
		entryCache: entryCache,
		logger:     &logger,
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
