// Copyright (C) 2023-2024 Holger de Carne and contributors
//
// This software may be modified and distributed under the terms
// of the MIT license.  See the LICENSE file for details.

package certstore

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"maps"

	"github.com/tdrn-org/go-certstore/certs"
	"github.com/tdrn-org/go-certstore/keys"
	"github.com/tdrn-org/go-certstore/storage"
)

// RegistryEntries represents a traversable collection of store entries.
type RegistryEntries struct {
	registry *Registry
	names    storage.Names
}

// Next gets the next store entry in the collection.
//
// nil is returned if the collection is exausted.
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

// Find looks up the next store entry in the collection matching the submitted match function.
//
// nil is returned if the none of the remaining store entries matches.
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

// RegistryEntry represents a single store entry.
type RegistryEntry struct {
	registry           *Registry
	name               string
	key                crypto.PrivateKey
	certificate        *x509.Certificate
	certificateRequest *x509.CertificateRequest
	revocationList     *x509.RevocationList
	attributes         map[string]string
}

// Name gets the name of the store entry.
func (entry *RegistryEntry) Name() string {
	return entry.name
}

// IsRoot reports whether this store entry represents a root certificate.
//
// A store entry represents a root certificate if it contains a certificate and the latter is self-signed.
func (entry *RegistryEntry) IsRoot() bool {
	if entry.certificate == nil {
		return false
	}
	return certs.IsRoot(entry.certificate)
}

// IsCA reports whether this store entry represents a certificate authority.
//
// A store entry represents a certificate authoritiy if it contains a certificate and the latter is entitled to sign certifictes.
func (entry *RegistryEntry) IsCA() bool {
	if entry.certificate == nil {
		return false
	}
	return entry.certificate.IsCA
}

// CanIssue determines if this store entry can be used to issue new certificates for the submitted key usage.
//
// I order to be able to issue new certificates a store entry must match the following prerequisites:
//
//  1. entry contains certificate ([HasCertificate]) and key ([HasKey])
//  2. the contained certificate must have a valid BasicConstraints extension ([x509.Certificate.BasicConstraintsValid])
//  3. the contained certificate must be marked as a CA ([IsCA])
//  4. the contained certificate's key usage matches the submitted one.
func (entry *RegistryEntry) CanIssue(keyUsage x509.KeyUsage) bool {
	return entry.key != nil && entry.certificate != nil && entry.certificate.BasicConstraintsValid && entry.certificate.IsCA && (entry.certificate.KeyUsage&keyUsage) == keyUsage
}

// HasKey reports whether this store entry contains a key.
func (entry *RegistryEntry) HasKey() bool {
	return entry.key != nil
}

// Key gets the store entry's key.
//
// nil is returned if the store entry does not contain a key.
//
// Invoking this function is recorded in the audit log using the the submitted user name.
func (entry *RegistryEntry) Key(user string) crypto.PrivateKey {
	if entry.key != nil {
		entry.registry.audit(auditAccessKey, entry.name, user)
	}
	return entry.key
}

// HasCertificate reports whether this store entry contains a certificate.
func (entry *RegistryEntry) HasCertificate() bool {
	return entry.certificate != nil
}

// Certificate gets the store entry's certificate.
//
// nil is returned if the store entry does not contain a certificate.
func (entry *RegistryEntry) Certificate() *x509.Certificate {
	return entry.certificate
}

func (entry *RegistryEntry) Export(out io.Writer, format ExportFormat, option ExportOption, password string, user string) error {
	if entry.certificate == nil {
		return ErrNoCertificate
	}
	var chain []*x509.Certificate
	if (option & ExportOptionChain) == ExportOptionChain {
		roots, intermediates, err := entry.registry.CertPools()
		if err != nil {
			return err
		}
		chains, err := entry.certificate.Verify(x509.VerifyOptions{
			Roots:         roots,
			Intermediates: intermediates,
			CurrentTime:   entry.certificate.NotBefore})
		if err == nil {
			if len(chains[0]) == 1 || (option&ExportOptionFullChain) == ExportOptionFullChain {
				chain = chains[0][1:]
			} else {
				chain = chains[0][1 : len(chains[0])-1]
			}
		}
	}
	var key crypto.PrivateKey
	if (option & ExportOptionKey) == ExportOptionKey {
		key = entry.Key(user)
	}
	err := format.CanExport(entry.certificate, chain, key)
	if err != nil {
		return err
	}
	return format.Export(out, entry.certificate, chain, key, password)
}

// HasCertificateRequest reports whether this store entry contains a certificate request.
func (entry *RegistryEntry) HasCertificateRequest() bool {
	return entry.certificateRequest != nil
}

// CertificateRequest gets the store entry's certificate request.
//
// nil is returned if the store entry does not contain a certificate request.
func (entry *RegistryEntry) CertificateRequest() *x509.CertificateRequest {
	return entry.certificateRequest
}

// ResetRevocationList resets the store entry's revocation list using the submitted [certs.RevocationListFactory].
//
// The newly created [x509.RevocationList] is returned.
// If the store entry is not suitable for signing a revocation list, [ErrInvalidIssuer] is returned.
//
// Invoking this function is recorded in the audit log using the the submitted user name.
func (entry *RegistryEntry) ResetRevocationList(factory certs.RevocationListFactory, user string) (*x509.RevocationList, error) {
	if !entry.CanIssue(x509.KeyUsageCRLSign) {
		return nil, ErrInvalidIssuer
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

// HasRevocationList reports whether this store entry contains a revocation list.
func (entry *RegistryEntry) HasRevocationList() bool {
	return entry.revocationList != nil
}

// RevocationList gets the store entry's revocation list.
//
// nil is returned if the store entry does not contain a revocation list.
func (entry *RegistryEntry) RevocationList() *x509.RevocationList {
	return entry.revocationList
}

// Attributes gets the attributes (key value pairs) associated with the store entry.
func (entry *RegistryEntry) Attributes() map[string]string {
	return maps.Clone(entry.attributes)
}

// SetAttributes sets the attributes (key value pairs) associated with the store entry.
//
// Any previously set attributes are overwritten or removed if no longer defined.
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
	encrypted := gcm.Seal(nonce, nonce, data, nil)
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
