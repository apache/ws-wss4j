/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.wss4j.common.crypto;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.util.Loader;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * A certificate carrying a malformed key identifier extension reaches these paths from the wire.
 * The decoder signals a malformed extension with an IllegalArgumentException, which must not
 * escape a trust path declared to throw WSSecurityException.
 */
public class MalformedKeyIdentifierTest {

    /**
     * Self-signed, CN=malformed-aki. Its AuthorityKeyIdentifier extnValue is
     * 04 08 30 05 80 03 01 02 03 00 -- a well formed SEQUENCE followed by a trailing byte.
     */
    private static final String MALFORMED_AKI_CERT =
          "MIIBuTCCASKgAwIBAgIBATANBgkqhkiG9w0BAQsFADAYMRYwFAYDVQQDDA1tYWxmb3JtZWQtYWtp"
        + "MB4XDTI1MDEwMTAwMDAwMFoXDTM1MDEwMTAwMDAwMFowGDEWMBQGA1UEAwwNbWFsZm9ybWVkLWFr"
        + "aTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAq6urq6urq6urq6urq6urq6urq6urq6urq6ur"
        + "q6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6ur"
        + "q6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6sCAwEAAaMTMBEwDwYD"
        + "VR0jBAgwBYADAQIDADANBgkqhkiG9w0BAQsFAAOBgQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==";

    /**
     * Self-signed, CN=malformed-ski. Its SubjectKeyIdentifier extnValue is
     * 04 09 04 84 7F FF FF FF 01 02 03 -- an inner OCTET STRING declaring Integer.MAX_VALUE bytes.
     */
    private static final String MALFORMED_SKI_CERT =
          "MIIBujCCASOgAwIBAgIBATANBgkqhkiG9w0BAQsFADAYMRYwFAYDVQQDDA1tYWxmb3JtZWQtc2tp"
        + "MB4XDTI1MDEwMTAwMDAwMFoXDTM1MDEwMTAwMDAwMFowGDEWMBQGA1UEAwwNbWFsZm9ybWVkLXNr"
        + "aTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAq6urq6urq6urq6urq6urq6urq6urq6urq6ur"
        + "q6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6ur"
        + "q6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6sCAwEAAaMUMBIwEAYD"
        + "VR0OBAkEhH////8BAgMwDQYJKoZIhvcNAQELBQADgYEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    /**
     * A received certificate whose AuthorityKeyIdentifier will not decode must fail trust
     * verification with a WSSecurityException, not an unchecked exception.
     */
    @Test
    public void testMerlinAKIRejectsMalformedAuthorityKeyIdentifier() throws Exception {
        X509Certificate cert = decode(MALFORMED_AKI_CERT, "2.5.29.35"); //NOPMD

        MerlinAKI crypto = new MerlinAKI();
        crypto.setTrustStore(loadKeyStore("keys/wss40CA.jks", "security"));

        WSSecurityException ex = assertThrows(
            WSSecurityException.class,
            () -> crypto.verifyTrust(new X509Certificate[]{cert}, false, null)
        );
        assertNotNull(ex);
    }

    /**
     * A truststore entry whose SubjectKeyIdentifier will not decode is skipped rather than
     * failing the lookup. The certificate under test is not trusted, so every alias is visited
     * and the malformed entry is guaranteed to be reached; trust must then fail with a
     * WSSecurityException rather than an unchecked exception from the skipped entry.
     */
    @Test
    public void testMerlinAKISkipsTruststoreEntryWithMalformedSubjectKeyIdentifier() throws Exception {
        X509Certificate untrusted = (X509Certificate)loadKeyStore("keys/wss86.keystore", "security")
            .getCertificate("wss86");
        assertNotNull(untrusted);

        KeyStore trustStore = loadKeyStore("keys/wss40CA.jks", "security");
        trustStore.setCertificateEntry("malformed-ski", decode(MALFORMED_SKI_CERT, "2.5.29.14")); //NOPMD

        MerlinAKI crypto = new MerlinAKI();
        crypto.setTrustStore(trustStore);

        WSSecurityException ex = assertThrows(
            WSSecurityException.class,
            () -> crypto.verifyTrust(new X509Certificate[]{untrusted}, false, null)
        );
        assertEquals(WSSecurityException.ErrorCode.FAILURE, ex.getErrorCode());
    }

    private X509Certificate decode(String base64Certificate, String expectedExtensionOid) throws Exception {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        X509Certificate cert;
        try (InputStream input = new ByteArrayInputStream(Base64.getDecoder().decode(base64Certificate))) {
            cert = (X509Certificate)certificateFactory.generateCertificate(input);
        }
        // a JDK that rejects the malformed extension outright leaves nothing for us to decode
        Assumptions.assumeTrue(cert.getExtensionValue(expectedExtensionOid) != null);
        return cert;
    }

    private KeyStore loadKeyStore(String path, String password) throws Exception {
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        ClassLoader loader = Loader.getClassLoader(MalformedKeyIdentifierTest.class);
        try (InputStream input = Merlin.loadInputStream(loader, path)) {
            keyStore.load(input, password.toCharArray());
        }
        return keyStore;
    }
}
