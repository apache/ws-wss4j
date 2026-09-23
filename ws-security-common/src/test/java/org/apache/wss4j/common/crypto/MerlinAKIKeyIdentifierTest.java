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

import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.util.Loader;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * MerlinAKI finds the issuing certificate by matching the received certificate's
 * AuthorityKeyIdentifier against the SubjectKeyIdentifier of the store entries. A certificate
 * carrying neither extension yields an empty identifier, which is not an identifier at all and
 * must not be matched against anything.
 */
public class MerlinAKIKeyIdentifierTest {

    @BeforeAll
    public static void setup() throws Exception {
        WSProviderConfig.init();
    }

    /**
     * A certificate with no AuthorityKeyIdentifier used to match every store entry that has no
     * SubjectKeyIdentifier of its own, because both read as an empty byte array. An unrelated
     * entry was then put forward as the issuer; the certificate path validation that follows
     * rejected it, but on the strength of the path failing rather than of there being no issuer
     * to look up. It is now rejected for the reason that actually holds.
     */
    @Test
    public void testCertificateWithNoAuthorityKeyIdentifierMatchesNothing() throws Exception {
        X509Certificate certificateWithoutAki = getCertificate("keys/wss40.p12", "security", "wss40");
        assertNull(certificateWithoutAki.getExtensionValue("2.5.29.35"),
                   "This test needs a certificate with no AuthorityKeyIdentifier");

        X509Certificate certificateWithoutSki = getCertificate("keys/wss40.jks", "security", "wss40ec");
        assertNull(certificateWithoutSki.getExtensionValue("2.5.29.14"),
                   "This test needs a trusted certificate with no SubjectKeyIdentifier");

        KeyStore trustStore = KeyStore.getInstance("JKS");
        trustStore.load(null, null);
        trustStore.setCertificateEntry("no-subject-key-identifier", certificateWithoutSki);

        MerlinAKI crypto = new MerlinAKI();
        crypto.setTrustStore(trustStore);

        WSSecurityException ex = assertThrows(WSSecurityException.class,
            () -> crypto.verifyTrust(new X509Certificate[] {certificateWithoutAki}, false, null));

        // No issuer was looked up at all, rather than an unrelated one being tried and failing
        // path validation - which would arrive here wrapping a CertPathValidatorException.
        assertNull(ex.getCause(), "Expected no issuer to be selected, but one was and it failed "
                                  + "path validation: " + ex.getMessage());
        assertEquals(WSSecurityException.ErrorCode.FAILURE, ex.getErrorCode());

        // Deliberately asserted on the message ID rather than on the formatted message. The text
        // is rendered through Santuario's global I18n bundle, which is whichever bundle is
        // installed first in the JVM and never replaced afterwards. If anything initialises
        // Santuario before WSProviderConfig.init() installs WSS4JResourceBundle, "certpath" stops
        // resolving and every WSS4J message degrades to "No message with ID ... found in resource
        // bundle ...". That is a property of the JVM the test happens to share, not of the code
        // under test, and it made this assertion fail under a full module test run while passing
        // when the class was run on its own. The message ID is stable either way.
        assertEquals("certpath", ex.getMsgID());
    }

    private static X509Certificate getCertificate(String keyStoreFile, String password, String alias)
        throws Exception {
        ClassLoader loader = Loader.getClassLoader(MerlinAKIKeyIdentifierTest.class);
        KeyStore keyStore = KeyStore.getInstance(keyStoreFile.endsWith(".p12") ? "PKCS12" : "JKS");
        try (InputStream input = Merlin.loadInputStream(loader, keyStoreFile)) {
            keyStore.load(input, password.toCharArray());
        }
        X509Certificate cert = (X509Certificate)keyStore.getCertificate(alias);
        assertNotNull(cert, "No certificate for alias " + alias + " in " + keyStoreFile);
        return cert;
    }
}
