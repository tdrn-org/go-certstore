// Copyright (C) 2023-2024 Holger de Carne and contributors
//
// This software may be modified and distributed under the terms
// of the MIT license.  See the LICENSE file for details.

package certs

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"slices"
	"strconv"
	"strings"
)

const KeyUsageExtensionName = "KeyUsage"
const KeyUsageExtensionOID = "2.5.29.15"

var keyUsages = []x509.KeyUsage{
	x509.KeyUsageDigitalSignature,
	x509.KeyUsageContentCommitment,
	x509.KeyUsageKeyEncipherment,
	x509.KeyUsageDataEncipherment,
	x509.KeyUsageKeyAgreement,
	x509.KeyUsageCertSign,
	x509.KeyUsageCRLSign,
	x509.KeyUsageEncipherOnly,
	x509.KeyUsageDecipherOnly,
}

var keyUsageStrings = map[x509.KeyUsage]string{
	x509.KeyUsageDigitalSignature:  "digitalSignature",
	x509.KeyUsageContentCommitment: "contentCommitment",
	x509.KeyUsageKeyEncipherment:   "keyEncipherment",
	x509.KeyUsageDataEncipherment:  "dataEncipherment",
	x509.KeyUsageKeyAgreement:      "keyAgreement",
	x509.KeyUsageCertSign:          "keyCertSign",
	x509.KeyUsageCRLSign:           "cRLSign",
	x509.KeyUsageEncipherOnly:      "encipherOnly",
	x509.KeyUsageDecipherOnly:      "decipherOnly",
}

func KeyUsageString(keyUsage x509.KeyUsage) string {
	if keyUsage == 0 {
		return "-"
	}
	var keyUsageFlags x509.KeyUsage
	var builder strings.Builder
	for _, keyUsageFlag := range keyUsages {
		if (keyUsage & keyUsageFlag) == keyUsageFlag {
			keyUsageFlags |= keyUsageFlag
			if builder.Len() > 0 {
				builder.WriteString(", ")
			}
			builder.WriteString(keyUsageStrings[keyUsageFlag])
		}
	}
	unknownKeyUsage := keyUsage ^ keyUsageFlags
	if unknownKeyUsage != 0 {
		if builder.Len() > 0 {
			builder.WriteString(", ")
		}
		builder.WriteString("0x" + strconv.FormatUint(uint64(unknownKeyUsage), 16))
	}
	return builder.String()
}

const ExtKeyUsageExtensionName = "ExtKeyUsage"
const ExtKeyUsageExtensionOID = "2.5.29.37"

var extKeyUsages = []x509.ExtKeyUsage{
	x509.ExtKeyUsageAny,
	x509.ExtKeyUsageServerAuth,
	x509.ExtKeyUsageClientAuth,
	x509.ExtKeyUsageCodeSigning,
	x509.ExtKeyUsageEmailProtection,
	x509.ExtKeyUsageIPSECEndSystem,
	x509.ExtKeyUsageIPSECTunnel,
	x509.ExtKeyUsageIPSECUser,
	x509.ExtKeyUsageTimeStamping,
	x509.ExtKeyUsageOCSPSigning,
	x509.ExtKeyUsageMicrosoftServerGatedCrypto,
	x509.ExtKeyUsageNetscapeServerGatedCrypto,
	x509.ExtKeyUsageMicrosoftCommercialCodeSigning,
	x509.ExtKeyUsageMicrosoftKernelCodeSigning,
}

var extKeyUsageStrings = map[x509.ExtKeyUsage]string{
	x509.ExtKeyUsageAny:                            "any",
	x509.ExtKeyUsageServerAuth:                     "serverAuth",
	x509.ExtKeyUsageClientAuth:                     "clientAuth",
	x509.ExtKeyUsageCodeSigning:                    "codeSigning",
	x509.ExtKeyUsageEmailProtection:                "emailProtection",
	x509.ExtKeyUsageIPSECEndSystem:                 "ipsecEndSystem",
	x509.ExtKeyUsageIPSECTunnel:                    "ipsecTunnel",
	x509.ExtKeyUsageIPSECUser:                      "ipsecUser",
	x509.ExtKeyUsageTimeStamping:                   "timeStamping",
	x509.ExtKeyUsageOCSPSigning:                    "ocspSigning",
	x509.ExtKeyUsageMicrosoftServerGatedCrypto:     "microsoftServerGatedCrypto",
	x509.ExtKeyUsageNetscapeServerGatedCrypto:      "netscapeServerGatedCrypto",
	x509.ExtKeyUsageMicrosoftCommercialCodeSigning: "microsoftCommercialCodeSigning",
	x509.ExtKeyUsageMicrosoftKernelCodeSigning:     "microsoftKernelCodeSigning",
}

func ExtKeyUsageString(extKeyUsage []x509.ExtKeyUsage, unknownExtKeyUsage []asn1.ObjectIdentifier) string {
	if len(extKeyUsage) == 0 && len(unknownExtKeyUsage) == 0 {
		return "-"
	}
	var builder strings.Builder
	for _, extKeyUsageId := range extKeyUsages {
		index := slices.Index(extKeyUsage, extKeyUsageId)
		if index < 0 {
			continue
		}
		if builder.Len() > 0 {
			builder.WriteString(", ")
		}
		builder.WriteString(extKeyUsageStrings[extKeyUsageId])
	}
	for _, unknownExtKeyUsageId := range unknownExtKeyUsage {
		if builder.Len() > 0 {
			builder.WriteString(", ")
		}
		builder.WriteString(unknownExtKeyUsageId.String())
	}
	return builder.String()
}

const BasicConstraintsExtensionName = "BasicConstraints"
const BasicConstraintsExtensionOID = "2.5.29.19"

func BasicConstraintsString(isCA bool, maxPathLen int, maxPathLenZero bool) string {
	if !isCA {
		return "CA: no"
	}
	if maxPathLen < 0 || (maxPathLen == 0 && !maxPathLenZero) {
		return "CA: yes"
	}
	return fmt.Sprintf("CA: yes, pathLenConstraint: %d", maxPathLen)
}

const SubjectKeyIdentifierExtensionName = "SubjectKeyIdentifier"
const SubjectKeyIdentifierExtensionOID = "2.5.29.14"

const AuthorityKeyIdentifierExtensionName = "AuthorityKeyIdentifier"
const AuthorityKeyIdentifierExtensionOID = "2.5.29.35"

func KeyIdentifierString(keyId []byte) string {
	return RawExtensionString(keyId)
}

const SubjectAlternativeNameExtensionName = "SubjectAlternativeName"
const SubjectAlternativeNameExtensionOID = "2.5.29.17"

func SubjectAlternativeString(dnsNames []string, emailNames []string, ipNames []net.IP, uriNames []*url.URL) string {
	if len(dnsNames) == 0 && len(emailNames) == 0 && len(ipNames) == 0 && len(uriNames) == 0 {
		return "-"
	}
	var builder strings.Builder
	for _, dnsName := range dnsNames {
		if builder.Len() > 0 {
			builder.WriteString(", ")
		}
		builder.WriteString("DNS:")
		builder.WriteString(dnsName)
	}
	for _, emailName := range emailNames {
		if builder.Len() > 0 {
			builder.WriteString(", ")
		}
		builder.WriteString("Email:")
		builder.WriteString(emailName)
	}
	for _, ipName := range ipNames {
		if builder.Len() > 0 {
			builder.WriteString(", ")
		}
		builder.WriteString("IP:")
		builder.WriteString(ipName.String())
	}
	for _, uriName := range uriNames {
		if builder.Len() > 0 {
			builder.WriteString(", ")
		}
		builder.WriteString("URI:")
		builder.WriteString(uriName.String())
	}
	return builder.String()
}

const stringLimit = 32

func RawExtensionString(extension []byte) string {
	if len(extension) == 0 {
		return ""
	}
	var builder strings.Builder
	encoder := hex.NewEncoder(&builder)
	for i := range extension {
		if i >= stringLimit {
			builder.WriteString(":...")
			break
		}
		if builder.Len() > 0 {
			builder.WriteString(":")
		}
		encoder.Write(extension[i : i+1])
	}
	return builder.String()
}
