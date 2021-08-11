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

package org.apache.wss4j.common.util;

import org.junit.jupiter.api.Test;

import javax.security.auth.x500.X500Principal;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Demonstrate using all CA's known to openjdk 11, and the default jdk running tests that a comma delimited DN and the Dn obtained from x500Principal.getName()
 * produce the same output when consumed at receiving side using new X500Principal(string).
 */
public class DmCommaDelimiterSymmetryTest {

    private DnCommaDelimiter subject = new DnCommaDelimiter();

    @Test
    public void testThatACommaDelimitedDnStringAndABackSlashExcapedDnProducesTheSameX509PrincipalUsingDefaultTruststore()
            throws KeyStoreException, InvalidAlgorithmParameterException, CertificateException, NoSuchAlgorithmException, IOException {
        KeyStore keystore = loadDefaultKeyStore();
        assertAllCATransformsArequivalen(keystore);
    }

    @Test
    public void testThatACommaDelimitedDnStringAndABackSlashExcapedDnProducesTheSameX509Principal()
            throws KeyStoreException, InvalidAlgorithmParameterException, CertificateException, NoSuchAlgorithmException, IOException {
        KeyStore keystore = loadKeyStore("keys/cacerts-openjdk.jks", "changeit");

        assertAllCATransformsArequivalen(keystore);
    }

    private void assertAllCATransformsArequivalen(KeyStore keystore) throws KeyStoreException, InvalidAlgorithmParameterException {
        PKIXParameters params = new PKIXParameters(keystore);
        for (TrustAnchor ta : params.getTrustAnchors()) {
            X509Certificate cert = ta.getTrustedCert();
            assertThatTransformIsEquivalent(cert.getSubjectX500Principal().getName());
        }
    }


    private void assertThatTransformIsEquivalent(String dnString) {
        // The expected value below recreates what is done in the token class by recreating the  X500Principal using getName()
        // even though the calling methods already used a X500Principal.getName()  to pass the value in the first place ,
        // this seems wasteful but I believe there is a reason for this in the wss4j code ...
        // Searching for different RFC 2253 parsers , this one :
        // https://www.codeproject.com/Articles/9788/An-RFC-2253-Compliant-Distinguished-Name-Parser
        // mentioned that its not possible to recreate the original binary because of the RFC allows multibyte characters  using # encoding.
        // Indeed w/o this additional calls to X500Principal.getName() this test will fail for one of the CA which indeed uses # encoding
        // because the equals uses the X500Name.canonicalDn string for comparison which if used directly from the keystore would
        // still contain the multibyte characters.
        // Since wss4j does not send multibyte characters, this tests uses of new X500Principal(dnString)
        // accurately reflects change usage.

        X500Principal expected = new X500Principal(dnString);
        X500Principal recreatedX509principal = new X500Principal(subject.delimitRdnWithDoubleComma(dnString));
        assertEquals(expected, recreatedX509principal);
    }

    private KeyStore loadKeyStore(String path, String password) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        InputStream in = this.getClass().getClassLoader().getResourceAsStream(path);
        keystore.load(in, password.toCharArray());
        return keystore;
    }

    private KeyStore loadDefaultKeyStore() throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException {
        String filename = System.getProperty("java.home") + "/lib/security/cacerts".replace('/', File.separatorChar);
        FileInputStream is = new FileInputStream(filename);
        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        String password = "changeit";
        keystore.load(is, password.toCharArray());
        return keystore;
    }

}
