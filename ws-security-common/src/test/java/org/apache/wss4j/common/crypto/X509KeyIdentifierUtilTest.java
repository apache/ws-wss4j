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

import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.util.Loader;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * This is a test for X509KeyIdentifierUtil, which extracts AuthorityKeyIdentifier and
 * SubjectKeyIdentifier information from certificates.
 */
public class X509KeyIdentifierUtilTest {

    public X509KeyIdentifierUtilTest() {
        WSProviderConfig.init();
    }

    @Test
    public void testExtractKeyIdentifiers() throws Exception {
        // Load the keystore
        KeyStore keyStore = loadKeyStore("keys/wss40.jks", "security");
        assertNotNull(keyStore);

        X509Certificate cert = (X509Certificate)keyStore.getCertificate("wss40");
        assertNotNull(cert);

        // Get AuthorityKeyIdentifier from the cert
        byte[] keyIdentifierBytes = X509KeyIdentifierUtil.getAuthorityKeyIdentifierBytes(cert);
        assertNotNull(keyIdentifierBytes);

        // Now load the CA cert
        KeyStore caKeyStore = loadKeyStore("keys/wss40CA.jks", "security");
        assertNotNull(caKeyStore);

        X509Certificate caCert = (X509Certificate)caKeyStore.getCertificate("wss40CA");
        assertNotNull(caCert);

        // Get SubjectKeyIdentifier from the CA cert
        byte[] subjectKeyIdentifierBytes =
            X509KeyIdentifierUtil.getSubjectKeyIdentifierBytes(caCert);
        assertNotNull(subjectKeyIdentifierBytes);

        assertTrue(Arrays.equals(keyIdentifierBytes, subjectKeyIdentifierBytes));
    }

    @Test
    public void testExtractKeyIdentifiersFromDer() {
        byte[] expectedKeyIdentifier = {1, 2, 3};
        byte[] authorityKeyIdentifier = {4, 7, 48, 5, (byte)0x80, 3, 1, 2, 3};
        byte[] subjectKeyIdentifier = {4, 5, 4, 3, 1, 2, 3};

        assertArrayEquals(
            expectedKeyIdentifier,
            X509KeyIdentifierUtil.getAuthorityKeyIdentifierBytes(authorityKeyIdentifier)
        );
        assertArrayEquals(
            expectedKeyIdentifier,
            X509KeyIdentifierUtil.getSubjectKeyIdentifierBytes(subjectKeyIdentifier)
        );
    }

    @Test
    public void testAuthorityKeyIdentifierWithoutKeyIdentifier() {
        byte[] authorityKeyIdentifier = {4, 5, 48, 3, (byte)0x82, 1, 1};
        byte[] authorityIssuerAndSerial = {4, 10, 48, 8, (byte)0xA1, 3, 48, 1, 0, (byte)0x82, 1, 1};
        byte[] emptyAuthorityKeyIdentifier = {4, 2, 48, 0};

        assertNull(X509KeyIdentifierUtil.getAuthorityKeyIdentifierBytes(authorityKeyIdentifier));
        assertNull(X509KeyIdentifierUtil.getAuthorityKeyIdentifierBytes(authorityIssuerAndSerial));
        assertNull(X509KeyIdentifierUtil.getAuthorityKeyIdentifierBytes(emptyAuthorityKeyIdentifier));
    }

    @Test
    public void testRejectMalformedKeyIdentifiers() {
        byte[] truncatedSubjectKeyIdentifier = {4, 5, 4, 3, 1, 2};
        byte[] trailingAuthorityKeyIdentifier = {4, 7, 48, 5, (byte)0x80, 3, 1, 2, 3, 0};
        byte[] indefiniteLengthSubjectKeyIdentifier = {4, (byte)0x80, 4, 0, 0, 0};

        assertThrows(
            IllegalArgumentException.class,
            () -> X509KeyIdentifierUtil.getSubjectKeyIdentifierBytes(truncatedSubjectKeyIdentifier)
        );
        assertThrows(
            IllegalArgumentException.class,
            () -> X509KeyIdentifierUtil.getAuthorityKeyIdentifierBytes(trailingAuthorityKeyIdentifier)
        );
        assertThrows(
            IllegalArgumentException.class,
            () -> X509KeyIdentifierUtil.getSubjectKeyIdentifierBytes(indefiniteLengthSubjectKeyIdentifier)
        );
    }

    /**
     * BouncyCastleUtils is the pre-4.0.2 name of this class, kept as a deprecated delegate so
     * that code written against 4.0.1 and earlier still compiles and behaves the same.
     */
    @Test
    @SuppressWarnings("removal")
    public void testDeprecatedBouncyCastleUtilsDelegates() throws Exception {
        KeyStore keyStore = loadKeyStore("keys/wss40.jks", "security");
        X509Certificate cert = (X509Certificate)keyStore.getCertificate("wss40");
        assertNotNull(cert);

        assertArrayEquals(
            X509KeyIdentifierUtil.getAuthorityKeyIdentifierBytes(cert),
            BouncyCastleUtils.getAuthorityKeyIdentifierBytes(cert)
        );
        assertArrayEquals(
            X509KeyIdentifierUtil.getSubjectKeyIdentifierBytes(cert),
            BouncyCastleUtils.getSubjectKeyIdentifierBytes(cert)
        );
    }

    @Test
    public void testMerlinAKI() throws Exception {
        // Load the keystore
        KeyStore keyStore = loadKeyStore("keys/wss40.jks", "security");
        assertNotNull(keyStore);
        X509Certificate cert = (X509Certificate)keyStore.getCertificate("wss40");
        assertNotNull(cert);

        // Now load the CA keystore + instantiate MerlinAKI
        KeyStore caKeyStore = loadKeyStore("keys/wss40CA.jks", "security");
        assertNotNull(caKeyStore);
        MerlinAKI crypto = new MerlinAKI();
        crypto.setTrustStore(caKeyStore);

        // Verify trust...
        crypto.verifyTrust(new X509Certificate[]{cert}, false, null);

        // Now test with a non-trusted cert
        KeyStore badKeyStore = loadKeyStore("keys/wss86.keystore", "security");
        assertNotNull(badKeyStore);
        X509Certificate badCert = (X509Certificate)badKeyStore.getCertificate("wss86");
        assertNotNull(badCert);

        try {
            crypto.verifyTrust(new X509Certificate[]{badCert}, false, null);
            fail("Failure expected on trying to validate an untrusted cert");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.FAILURE);
        }
    }

    private KeyStore loadKeyStore(String path, String password) throws Exception {
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        ClassLoader loader = Loader.getClassLoader(X509KeyIdentifierUtilTest.class);
        InputStream input = Merlin.loadInputStream(loader, path);
        keyStore.load(input, password.toCharArray());
        input.close();

        return keyStore;
    }
}
