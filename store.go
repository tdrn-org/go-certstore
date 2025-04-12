// Copyright (C) 2023-2025 Holger de Carne and contributors
//
// This software may be modified and distributed under the terms
// of the MIT license.  See the LICENSE file for details.

// Package certstore provides functionality for creation and mantainenace of X.509 certificate stores.
package certstore

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"runtime"
	"strings"
	"time"

	"github.com/jellydator/ttlcache/v3"
	"github.com/tdrn-org/go-certstore/certs"
	"github.com/tdrn-org/go-certstore/storage"
)

// An ErrNoKey error indicates a missing key.
var ErrNoKey = errors.New("no key")

// An ErrNoCertificate error indicates a missing certificate.
var ErrNoCertificate = errors.New("no certificate")

// An ErrInvalidIssuer error indicates the given certificate is not suitable for the requested signing operation.
var ErrInvalidIssuer = errors.New("invalid issuer certificate")

// A MergeStatus shows the result of a merge operation.
type MergeStatus int

const (
	// MergeStatusNone indicates nothing to merge.
	MergeStatusNone MergeStatus = -1
	// MergeStatusNew indicates the merged security object is not related to any store entry (and therefore part of new store entry).
	MergeStatusNew MergeStatus = 0
	// MergeStatusAdd indicates the merged security object is related a store entry, but not yet known (and therefor added during a merge).
	MergeStatusAdd MergeStatus = 1
	// MergeStatusExists indicates the merged security object already exists in the store.
	MergeStatusExists MergeStatus = 2
)

func (status MergeStatus) combine(other MergeStatus) MergeStatus {
	if status == MergeStatusNew || status == MergeStatusAdd {
		return status
	}
	return other
}

// A Registry represents a X.509 certificate store.
type Registry struct {
	settings   *storeSettings
	backend    storage.Backend
	entryCache *ttlcache.Cache[string, *RegistryEntry]
	logger     *slog.Logger
}

// Name gets the registry name which is derived from the registry's storage location.
func (registry *Registry) Name() string {
	return fmt.Sprintf("Registry[%s]", registry.backend.URI())
}

// CreateCertificate creates a new X.509 certificate using the provided [certs.CertificateFactory].
//
// The name of the created store entry is returned. The returned name is derived
// from the submitted name, by making it unique. Means, if the submitted name is
// not already in use, it is returned as is. Otherwise it is made unique by appending
// a suffix.
//
// Invoking this function is recorded in the audit log using the the submitted user name.
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
	if err != nil {
		return "", err
	}
	registry.audit(auditCreateCertificate, createdName, user)
	return createdName, nil
}

// MergeCertificate merges a X.509 certificate into the store.
//
// Whether the merge is made permanent or not, is controlled by the given commit flag.
// If a store entry related to submitted certfiicate is already in the store, the name of the existing store entry is returned.
// Otherwise a new entry is created using the the given name.
// The returned merge status shows the exact result of the merge.
// Like for [CreateCertificate] the submitted name is used to derive the name of the added store entry.
//
// Invoking this function is recorded in the audit log using the the submitted user name.
func (registry *Registry) MergeCertificate(name string, certificate *x509.Certificate, user string, commit bool) (string, MergeStatus, error) {
	entry, mergeStatus, err := registry.findMergeEntryByCertificate(certificate)
	if err != nil {
		return "", mergeStatus, err
	}
	mergedName := name
	if entry != nil {
		mergedName = entry.Name()
	}
	if !commit {
		return mergedName, mergeStatus, nil
	}
	switch mergeStatus {
	case MergeStatusNew:
		data := &registryEntryData{}
		data.setCertificate(certificate)
		mergedName, err = registry.createEntryData(name, data)
		if err != nil {
			return mergedName, mergeStatus, err
		}
		registry.audit(auditMergeCertificate, mergedName, user)
	case MergeStatusAdd:
		err = entry.mergeCertificate(certificate)
		if err != nil {
			return mergedName, mergeStatus, err
		}
		registry.cacheDelete(mergedName)
		registry.audit(auditMergeCertificate, mergedName, user)
	case MergeStatusExists:
		// Nothing to do here
	}
	return mergedName, mergeStatus, nil
}

func (registry *Registry) findMergeEntryByCertificate(certificate *x509.Certificate) (*RegistryEntry, MergeStatus, error) {
	mergeStatus := MergeStatusNone
	entries, err := registry.Entries()
	if err != nil {
		return nil, mergeStatus, err
	}
	entry, err := entries.Find(func(entry *RegistryEntry) bool { return entry.matchCertificate(certificate) })
	if err != nil {
		return nil, mergeStatus, err
	}
	mergeStatus = MergeStatusNew
	if entry != nil {
		if entry.HasCertificate() {
			mergeStatus = MergeStatusExists
		} else {
			mergeStatus = MergeStatusAdd
		}
	}
	return entry, mergeStatus, nil
}

// CreateCertificateRequest creates a new X.509 certificate request using the provided [certs.CertificateRequestFactory].
//
// The name of the created store entry is returned. The returned name is derived
// from the submitted name, by making it unique. Means, if the submitted name is
// not already in use, it is returned as is. Otherwise it is made unique by appending
// a suffix.
//
// Invoking this function is recorded in the audit log using the the submitted user name.
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
	if err != nil {
		return "", err
	}
	registry.audit(auditCreateCertificateRequest, createdName, user)
	return createdName, nil
}

// MergeCertificateRequest merges a X.509 certificate request into the store.
//
// Whether the merge is made permanent or not, is controlled by the given commit flag.
// If a store entry related to submitted certfiicate request is already in the store, the name of the existing store entry is returned.
// Otherwise a new entry is created using the the given name.
// The returned merge status shows the exact result of the merge.
// Like for [CreateCertificateRequest] the submitted name is used to derive the name of the added store entry.
//
// Invoking this function is recorded in the audit log using the the submitted user name.
func (registry *Registry) MergeCertificateRequest(name string, certificateRequest *x509.CertificateRequest, user string, commit bool) (string, MergeStatus, error) {
	entry, mergeStatus, err := registry.findMergeEntryByCertificateRequest(certificateRequest)
	if err != nil {
		return "", mergeStatus, err
	}
	mergedName := name
	if entry != nil {
		mergedName = entry.Name()
	}
	if !commit {
		return mergedName, mergeStatus, nil
	}
	switch mergeStatus {
	case MergeStatusNew:
		data := &registryEntryData{}
		data.setCertificateRequest(certificateRequest)
		mergedName, err = registry.createEntryData(name, data)
		if err != nil {
			return mergedName, mergeStatus, err
		}
		registry.audit(auditMergeCertificateRequest, mergedName, user)
	case MergeStatusAdd:
		err = entry.mergeCertificateRequest(certificateRequest)
		if err != nil {
			return mergedName, mergeStatus, err
		}
		registry.cacheDelete(mergedName)
		registry.audit(auditMergeCertificateRequest, mergedName, user)
	case MergeStatusExists:
		// Nothing to do here
	}
	return mergedName, mergeStatus, nil
}

func (registry *Registry) findMergeEntryByCertificateRequest(certificateRequest *x509.CertificateRequest) (*RegistryEntry, MergeStatus, error) {
	mergeStatus := MergeStatusNone
	entries, err := registry.Entries()
	if err != nil {
		return nil, mergeStatus, err
	}
	entry, err := entries.Find(func(entry *RegistryEntry) bool { return entry.matchCertificateRequest(certificateRequest) })
	if err != nil {
		return nil, mergeStatus, err
	}
	mergeStatus = MergeStatusNew
	if entry != nil {
		if entry.HasCertificateRequest() {
			mergeStatus = MergeStatusExists
		} else {
			mergeStatus = MergeStatusAdd
		}
	}
	return entry, mergeStatus, nil
}

// MergeKey merges a X.509 certificate key into the store.
//
// Whether the merge is made permanent or not, is controlled by the given commit flag.
// If a store entry related to submitted certfiicate key is already in the store, the name of the existing store entry is returned.
// Otherwise a new entry is created using the the given name.
// The returned merge status shows the exact result of the merge.
// Like for [CreateCertificate] the submitted name is used to derive the name of the added store entry.
//
// Invoking this function is recorded in the audit log using the the submitted user name.
func (registry *Registry) MergeKey(name string, key crypto.PrivateKey, user string, commit bool) (string, MergeStatus, error) {
	entry, mergeStatus, err := registry.findMergeEntryByKey(key)
	if err != nil {
		return "", mergeStatus, err
	}
	mergedName := name
	if entry != nil {
		mergedName = entry.Name()
	}
	if !commit {
		return mergedName, mergeStatus, nil
	}
	switch mergeStatus {
	case MergeStatusNew:
		data := &registryEntryData{}
		data.setKey(key, registry.settings.Secret)
		mergedName, err = registry.createEntryData(name, data)
		if err != nil {
			return mergedName, mergeStatus, err
		}
		registry.audit(auditMergeKey, mergedName, user)
	case MergeStatusAdd:
		err = entry.mergeKey(key)
		if err != nil {
			return mergedName, mergeStatus, err
		}
		registry.cacheDelete(mergedName)
		registry.audit(auditMergeKey, mergedName, user)
	case MergeStatusExists:
		// Nothing to do here
	}
	return mergedName, mergeStatus, nil
}

func (registry *Registry) findMergeEntryByKey(key crypto.PrivateKey) (*RegistryEntry, MergeStatus, error) {
	mergeStatus := MergeStatusNone
	entries, err := registry.Entries()
	if err != nil {
		return nil, mergeStatus, err
	}
	entry, err := entries.Find(func(entry *RegistryEntry) bool { return entry.matchKey(key) })
	if err != nil {
		return nil, mergeStatus, err
	}
	mergeStatus = MergeStatusNew
	if entry != nil {
		if entry.HasKey() {
			mergeStatus = MergeStatusExists
		} else {
			mergeStatus = MergeStatusAdd
		}
	}
	return entry, mergeStatus, nil
}

// MergeKey merges a X.509 certificate revocation list into the store.
//
// Whether the merge is made permanent or not, is controlled by the given commit flag.
// If a store entry related to submitted certfiicate revocation list is already in the store, the name of the existing store entry is returned.
// Otherwise a new entry is created using the the given name.
// The returned merge status shows the exact result of the merge.
// Like for [CreateCertificate] the submitted name is used to derive the name of the added store entry.
//
// Invoking this function is recorded in the audit log using the the submitted user name.
func (registry *Registry) MergeRevocationList(name string, revocationList *x509.RevocationList, user string, commit bool) (string, MergeStatus, error) {
	entry, mergeStatus, err := registry.findMergeEntryByRevocationList(revocationList)
	if err != nil {
		return "", mergeStatus, err
	}
	mergedName := name
	if entry != nil {
		mergedName = entry.Name()
	}
	if !commit {
		return mergedName, mergeStatus, nil
	}
	switch mergeStatus {
	case MergeStatusNew:
		data := &registryEntryData{}
		data.setRevocationList(revocationList)
		mergedName, err = registry.createEntryData(name, data)
		if err != nil {
			return mergedName, mergeStatus, err
		}
		registry.audit(auditMergeRevocationList, mergedName, user)
	case MergeStatusAdd:
		err = entry.mergeRevocationList(revocationList)
		if err != nil {
			return mergedName, mergeStatus, err
		}
		registry.cacheDelete(mergedName)
		registry.audit(auditMergeRevocationList, mergedName, user)
	case MergeStatusExists:
		// Nothing to do here
	}
	return mergedName, mergeStatus, nil
}

func (registry *Registry) findMergeEntryByRevocationList(revocationList *x509.RevocationList) (*RegistryEntry, MergeStatus, error) {
	mergeStatus := MergeStatusNone
	entries, err := registry.Entries()
	if err != nil {
		return nil, mergeStatus, err
	}
	entry, err := entries.Find(func(entry *RegistryEntry) bool { return entry.matchRevocationList(revocationList) })
	if err != nil {
		return nil, mergeStatus, err
	}
	mergeStatus = MergeStatusNew
	if entry != nil {
		if entry.HasKey() {
			mergeStatus = MergeStatusExists
		} else {
			mergeStatus = MergeStatusAdd
		}
	}
	return entry, mergeStatus, nil
}

type MergeResult struct {
	Name                     string
	Status                   MergeStatus
	CertificateStatus        MergeStatus
	CertificateRequestStatus MergeStatus
	KeyStatus                MergeStatus
	RevocationListStatus     MergeStatus
}

// Merge merges another X.509 certificate store into the store.
//
// The submitted store is merged by merging each of its entries individually.
//
// Invoking this function is recorded in the audit log using the the submitted user name.
func (registry *Registry) Merge(other *Registry, user string, commit bool) ([]MergeResult, error) {
	mergeResults := make([]MergeResult, 0)
	otherEntries, err := other.Entries()
	if err != nil {
		return mergeResults, err
	}
	for {
		otherEntry, err := otherEntries.Next()
		if err != nil {
			return mergeResults, err
		}
		if otherEntry == nil {
			break
		}
		mergeResult, err := registry.mergeEntry(otherEntry, user, commit)
		if err != nil {
			return mergeResults, err
		}
		mergeResults = append(mergeResults, mergeResult)
	}
	return mergeResults, nil
}

func (registry *Registry) mergeEntry(entry *RegistryEntry, user string, commit bool) (MergeResult, error) {
	name := ""
	if commit {
		name = "Imported"
	}
	mergeResult := MergeResult{
		Name:                     "",
		CertificateStatus:        MergeStatusNone,
		CertificateRequestStatus: MergeStatusNone,
		KeyStatus:                MergeStatusNone,
		RevocationListStatus:     MergeStatusNone,
	}
	if entry.HasCertificate() {
		mergedName, certificateStatus, err := registry.MergeCertificate(name, entry.Certificate(), user, commit)
		if err != nil {
			return mergeResult, err
		}
		mergeResult.Name = mergedName
		mergeResult.CertificateStatus = certificateStatus
	}
	if entry.HasCertificateRequest() {
		mergedName, certificateRequestStatus, err := registry.MergeCertificateRequest("Imported certificate request", entry.CertificateRequest(), user, commit)
		if err != nil {
			return mergeResult, err
		}
		mergeResult.Name = mergedName
		mergeResult.CertificateRequestStatus = certificateRequestStatus
	}
	if entry.HasKey() {
		mergedName, keyStatus, err := registry.MergeKey("Imported key", entry.Key(user), user, commit)
		if err != nil {
			return mergeResult, err
		}
		mergeResult.Name = mergedName
		mergeResult.KeyStatus = keyStatus
	}
	if entry.HasRevocationList() {
		mergedName, revocationListStatus, err := registry.MergeRevocationList("Imported revocation list", entry.RevocationList(), user, commit)
		if err != nil {
			return mergeResult, err
		}
		mergeResult.Name = mergedName
		mergeResult.RevocationListStatus = revocationListStatus
	}
	mergeResult.Status = mergeResult.CertificateStatus.combine(mergeResult.CertificateRequestStatus).combine(mergeResult.KeyStatus).combine(mergeResult.RevocationListStatus)
	return mergeResult, nil
}

// Entries lists all entries of the store.
//
// The returned [RegistryEntries] collection is sorted in lexical order and backed up by the store.
// Deleting a store entry after querying the [RegistryEntries] collection will cause a [storage.ErrNotExist]
// whenever the deleted entry is traversed.
func (registry *Registry) Entries() (*RegistryEntries, error) {
	names, err := registry.backend.List()
	if err != nil {
		return nil, err
	}
	return &RegistryEntries{registry: registry, names: names}, nil
}

// Entry looks up the entry with the submitted name in the store.
//
// If the submitted name does not exist, [storage.ErrNotExist] is returned.
func (registry *Registry) Entry(name string) (*RegistryEntry, error) {
	cached := registry.cacheGet(name)
	if cached != nil {
		return cached.Value(), nil
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
	registry.cacheSet(name, entry)
	return entry, nil
}

// Delete deletes the entry with the submitted name from the store.
//
// If the submitted name does not exist, [storage.ErrNotExist] is returned.
func (registry *Registry) Delete(name string, user string) error {
	err := registry.backend.Delete(name)
	if err != nil {
		return err
	}
	registry.cacheDelete(name)
	registry.audit(auditDelete, name, user)
	return nil
}

// CertPools wraps this store's entries into a [x509.CertPool].
//
// The first returned pool contains the root certificates. The second on the intermediate certificates.
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

func (registry *Registry) cacheGet(name string) *ttlcache.Item[string, *RegistryEntry] {
	if registry.entryCache != nil {
		return registry.entryCache.Get(name)
	}
	return nil
}

func (registry *Registry) cacheSet(name string, entry *RegistryEntry) {
	if registry.entryCache != nil {
		registry.entryCache.Set(name, entry, ttlcache.DefaultTTL)
	}
}

func (registry *Registry) cacheDelete(name string) {
	if registry.entryCache != nil {
		registry.entryCache.Delete(name)
	}
}

const storeAuditName = ".audit"

func (registry *Registry) audit(pattern auditPattern, name string, user string) {
	message := pattern.sprintf(name, user)
	registry.logger.Info("audit", slog.String("message", message))
	err := registry.backend.Log(storeAuditName, message)
	if err != nil {
		registry.logger.Error("failed to write audit log", slog.String("message", message), slog.Any("err", err))
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
	auditDelete                   auditPattern = "%d;Delete;-;%s;%s"
)

func (pattern auditPattern) sprintf(name string, user string) string {
	return fmt.Sprintf(string(pattern), time.Now().UnixMilli(), name, user)
}

const storeSettingsName = ".store"

type storeSettings struct {
	Secret string `json:"secret"`
}

// NewStore creates a certificate store using the submitted storage backend and parameters.
//
// If the submitted storage location is used for the first time, a new certificate store is setup.
// Using the same storage location again, opens the previously created certificate store.
func NewStore(backend storage.Backend, cacheTTL time.Duration) (*Registry, error) {
	logger := slog.With(slog.String("registry", backend.URI()))
	settings, err := newStoreSettings(backend, logger)
	if err != nil {
		return nil, err
	}
	var entryCache *ttlcache.Cache[string, *RegistryEntry]
	if cacheTTL > 0 {
		entryCache = ttlcache.New(ttlcache.WithTTL[string, *RegistryEntry](cacheTTL))
		go entryCache.Start()
		runtime.SetFinalizer(entryCache, func(cache *ttlcache.Cache[string, *RegistryEntry]) { cache.Stop() })
	}
	return &Registry{
		settings:   settings,
		backend:    backend,
		entryCache: entryCache,
		logger:     logger,
	}, nil
}

func newStoreSettings(backend storage.Backend, logger *slog.Logger) (*storeSettings, error) {
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

func initStoreSettings(backend storage.Backend, logger *slog.Logger, settings *storeSettings) error {
	logger.Info("initializing store settings...")
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
