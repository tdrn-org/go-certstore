// Copyright (C) 2023-2024 Holger de Carne and contributors
//
// This software may be modified and distributed under the terms
// of the MIT license.  See the LICENSE file for details.

package certstore

import (
	"crypto"
	"crypto/x509"
	"io"

	"github.com/tdrn-org/go-certstore/certs"
)

type ExportOption int

const (
	ExportOptionKey       ExportOption = 1 << 0
	ExportOptionChain     ExportOption = 1 << 1
	ExportOptionFullChain ExportOption = ExportOptionChain | (1 << 2)
	ExportOptionDefault   ExportOption = ExportOptionKey | ExportOptionChain
)

var ExportFormatPEM ExportFormat = &exportFormatPEM{}
var ExportFormatDER ExportFormat = &exportFormatDER{}
var ExportFormatPKCS12 ExportFormat = &exportFormatPKCS12{}

type ExportFormat interface {
	Name() string
	ContentType() string
	CanExport(certificate *x509.Certificate, chain []*x509.Certificate, key crypto.PrivateKey) error
	Export(out io.Writer, certificate *x509.Certificate, chain []*x509.Certificate, key crypto.PrivateKey, password string) error
}

type exportFormatPEM struct{}

func (format *exportFormatPEM) Name() string {
	return "PEM"
}

func (format *exportFormatPEM) ContentType() string {
	return "application/zip"
}

func (format *exportFormatPEM) CanExport(certificate *x509.Certificate, chain []*x509.Certificate, key crypto.PrivateKey) error {
	if certificate == nil {
		return ErrNoCertificate
	}
	return nil
}

func (format *exportFormatPEM) Export(out io.Writer, certificate *x509.Certificate, chain []*x509.Certificate, key crypto.PrivateKey, password string) error {
	return certs.ExportPEM(out, certificate, chain, key)
}

type exportFormatDER struct{}

func (format *exportFormatDER) ContentType() string {
	return "application/zip"
}

func (format *exportFormatDER) Name() string {
	return "DER"
}

func (format *exportFormatDER) CanExport(certificate *x509.Certificate, chain []*x509.Certificate, key crypto.PrivateKey) error {
	if certificate == nil {
		return ErrNoCertificate
	}
	return nil
}

func (format *exportFormatDER) Export(out io.Writer, certificate *x509.Certificate, chain []*x509.Certificate, key crypto.PrivateKey, password string) error {
	return certs.ExportDER(out, certificate, chain, key)
}

type exportFormatPKCS12 struct{}

func (format *exportFormatPKCS12) Name() string {
	return "PKCS#12"
}

func (format *exportFormatPKCS12) ContentType() string {
	return "application/octet-stream"
}

func (format *exportFormatPKCS12) CanExport(certificate *x509.Certificate, chain []*x509.Certificate, key crypto.PrivateKey) error {
	if certificate == nil {
		return ErrNoCertificate
	}
	if key == nil {
		return ErrNoKey
	}
	return nil
}

func (format *exportFormatPKCS12) Export(out io.Writer, certificate *x509.Certificate, chain []*x509.Certificate, key crypto.PrivateKey, password string) error {
	return certs.ExportPKCS12(out, certificate, chain, key, password)
}
