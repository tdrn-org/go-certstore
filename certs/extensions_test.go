// Copyright (C) 2023-2024 Holger de Carne and contributors
//
// This software may be modified and distributed under the terms
// of the MIT license.  See the LICENSE file for details.

package certs_test

import (
	"crypto/x509"
	"encoding/asn1"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tdrn-org/go-certstore/certs"
)

func TestKeyUsageString(t *testing.T) {
	require.Equal(t, "-", certs.KeyUsageString(0))
	require.Equal(t, "keyCertSign", certs.KeyUsageString(x509.KeyUsageCertSign))
	require.Equal(t, "digitalSignature, contentCommitment, keyEncipherment, dataEncipherment, keyAgreement, keyCertSign, cRLSign, encipherOnly, decipherOnly, 0xfe00", certs.KeyUsageString(0xffff))
}

func TestExtKeyUsageString(t *testing.T) {
	require.Equal(t, "-", certs.ExtKeyUsageString([]x509.ExtKeyUsage{}, []asn1.ObjectIdentifier{}))
	require.Equal(t, "any, 1.2.3.4", certs.ExtKeyUsageString([]x509.ExtKeyUsage{x509.ExtKeyUsageAny}, []asn1.ObjectIdentifier{asn1.ObjectIdentifier([]int{1, 2, 3, 4})}))
}

const basicConstraintsNoCA = "CA: no"
const basicConstratinsCAWithoutPathLenConstraint = "CA: yes"
const basicConstratinsCAWithPathLenConstraint = "CA: yes, pathLenConstraint: 2"

func TestBasicConstraintsString(t *testing.T) {
	require.Equal(t, basicConstraintsNoCA, certs.BasicConstraintsString(false, 0, false))
	require.Equal(t, basicConstratinsCAWithoutPathLenConstraint, certs.BasicConstraintsString(true, -1, true))
	require.Equal(t, basicConstratinsCAWithoutPathLenConstraint, certs.BasicConstraintsString(true, -1, false))
	require.Equal(t, basicConstratinsCAWithoutPathLenConstraint, certs.BasicConstraintsString(true, 0, false))
	require.Equal(t, basicConstratinsCAWithPathLenConstraint, certs.BasicConstraintsString(true, 2, false))
	require.Equal(t, basicConstratinsCAWithPathLenConstraint, certs.BasicConstraintsString(true, 2, true))
}

func TestKeyIdentiferString(t *testing.T) {
	keyId1 := []byte{0x88, 0x1b, 0xd6, 0x08, 0x08, 0xe2, 0xef, 0x84, 0x74, 0xc7, 0x1c, 0x2c, 0x87, 0xd1, 0xd6, 0x87, 0x6b, 0x7b, 0x94, 0x59}
	require.Equal(t, "88:1b:d6:08:08:e2:ef:84:74:c7:1c:2c:87:d1:d6:87:6b:7b:94:59", certs.KeyIdentifierString(keyId1))
	keyId2 := []byte{0x88, 0x1b, 0xd6, 0x08, 0x08, 0xe2, 0xef, 0x84, 0x74, 0xc7, 0x1c, 0x2c, 0x87, 0xd1, 0xd6, 0x87, 0x6b, 0x7b, 0x94, 0x59, 0x88, 0x1b, 0xd6, 0x08, 0x08, 0xe2, 0xef, 0x84, 0x74, 0xc7, 0x1c, 0x2c, 0x87, 0xd1, 0xd6, 0x87, 0x6b, 0x7b, 0x94, 0x59}
	require.Equal(t, "88:1b:d6:08:08:e2:ef:84:74:c7:1c:2c:87:d1:d6:87:6b:7b:94:59:88:1b:d6:08:08:e2:ef:84:74:c7:1c:2c:...", certs.KeyIdentifierString(keyId2))
}
