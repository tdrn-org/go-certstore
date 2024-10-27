// Copyright (C) 2023-2024 Holger de Carne and contributors
//
// This software may be modified and distributed under the terms
// of the MIT license.  See the LICENSE file for details.

package acme

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
	"github.com/hdecarne-github/go-certstore/keys"
)

// A ProviderRegistration contains an ACME provider's registration information. This includes at least the necessary
// information to register. In case a registration has been performed in the past, the ACME provider's registration
// key and token is also included. However the latter may be outdated.
type ProviderRegistration struct {
	// Provider contains the name of the ACME provider, this registration is related to.
	Provider string `json:"provider"`
	// Email contains the email to use for registering to the ACME provider.
	Email string `json:"email"`
	// EncodedKey contains the encoded private key used for registering to the ACME provider.
	EncodedKey string `json:"key"`
	// Registration contains the registration token returned from the ACME provider during the registration.
	Registration *registration.Resource
}

// GetEmail gets the email to use for registering to the ACME provider.
//
// This function is part of [registration.User] interface.
func (providerRegistration *ProviderRegistration) GetEmail() string {
	return providerRegistration.Email
}

// GetRegistration gets the token returned by a previous run registration (may be nil).
//
// This function is part of [registration.User] interface.
func (providerRegistration *ProviderRegistration) GetRegistration() *registration.Resource {
	return providerRegistration.Registration
}

// GetPrivateKey gets the private key used for a previous performed registration (may be nil).
//
// This function is part of [registration.User] interface.
func (providerRegistration *ProviderRegistration) GetPrivateKey() crypto.PrivateKey {
	if providerRegistration.EncodedKey == "" {
		return nil
	}
	keyBytes, err := base64.StdEncoding.DecodeString(providerRegistration.EncodedKey)
	if err != nil {
		return nil
	}
	key, err := x509.ParsePKCS8PrivateKey(keyBytes)
	if err != nil {
		return nil
	}
	return key
}

func (providerRegistration *ProviderRegistration) matches(providerRegistration2 *ProviderRegistration) bool {
	return providerRegistration.Provider == providerRegistration2.Provider && providerRegistration.Email == providerRegistration2.Email
}

func (providerRegistration *ProviderRegistration) isActive(client *lego.Client) bool {
	if providerRegistration.Registration == nil {
		return false
	}
	_, err := client.Registration.QueryRegistration()
	return err == nil
}

func (providerRegistration *ProviderRegistration) register(client *lego.Client) error {
	options := registration.RegisterOptions{TermsOfServiceAgreed: true}
	registrationResource, err := client.Registration.Register(options)
	if err != nil {
		return fmt.Errorf("failed to register at ACME provider '%s' (cause: %w)", providerRegistration.Provider, err)
	}
	providerRegistration.Registration = registrationResource
	return nil
}

func (providerRegistration *ProviderRegistration) updateProviderRegistrations(file *os.File) error {
	fileProviderRegistrations, err := unmarshalProviderRegistrations(file)
	if err != nil {
		return err
	}
	updateIndex := -1
	for i, fileProviderRegistration := range fileProviderRegistrations {
		if fileProviderRegistration.matches(providerRegistration) {
			updateIndex = i
			break
		}
	}
	if updateIndex >= 0 {
		fileProviderRegistrations[updateIndex] = *providerRegistration
	} else {
		fileProviderRegistrations = append(fileProviderRegistrations, *providerRegistration)
	}
	writeBytes, err := json.MarshalIndent(fileProviderRegistrations, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal registrations (cause: %w)", err)
	}
	_, err = file.Seek(0, 0)
	if err != nil {
		return fmt.Errorf("seek failed for file '%s' (cause: %w)", file.Name(), err)
	}
	err = file.Truncate(0)
	if err != nil {
		return fmt.Errorf("truncate failed for file '%s' (cause: %w)", file.Name(), err)
	}
	_, err = file.Write(writeBytes)
	if err != nil {
		return fmt.Errorf("write failed for file '%s' (cause: %w)", file.Name(), err)
	}
	return nil
}

func prepareProviderRegistration(provider *ProviderConfig, file *os.File, keyPairFactory keys.KeyPairFactory) (*ProviderRegistration, error) {
	registrations, err := unmarshalProviderRegistrations(file)
	if err != nil {
		return nil, err
	}
	for _, registration := range registrations {
		if registration.Provider == provider.Name {
			return &registration, nil
		}
	}
	key, err := keyPairFactory.New()
	if err != nil {
		return nil, err
	}
	keyBytes, err := x509.MarshalPKCS8PrivateKey(key.Private())
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key (cause: %w)", err)
	}
	registration := &ProviderRegistration{
		Provider:   provider.Name,
		Email:      provider.RegistrationEmail,
		EncodedKey: base64.StdEncoding.EncodeToString(keyBytes),
	}
	return registration, nil
}

func unmarshalProviderRegistrations(file *os.File) ([]ProviderRegistration, error) {
	_, err := file.Seek(0, 0)
	if err != nil {
		return nil, fmt.Errorf("seek failed for file '%s' (cause: %w)", file.Name(), err)
	}
	readBytes := make([]byte, 0, 4096)
	for {
		read, err := file.Read(readBytes[len(readBytes):cap(readBytes)])
		if read == 0 {
			break
		}
		if err != nil {
			return nil, err
		}
		readBytes = readBytes[:len(readBytes)+read]
		if len(readBytes) == cap(readBytes) {
			readBytes = append(readBytes, 0)[:len(readBytes)]
		}
	}
	registrations := make([]ProviderRegistration, 0)
	if len(readBytes) > 0 {
		err := json.Unmarshal(readBytes, &registrations)
		if err != nil {
			return nil, err
		}
	}
	return registrations, nil
}
