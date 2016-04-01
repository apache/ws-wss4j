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

import org.apache.wss4j.common.util.Loader;

/**
 * This is a test for extracting AuthorityKeyIdentifier/SubjectKeyIdentifier information from
 * the certs using BouncyCastle.
 */
public class AuthorityKeyIdentifierTest extends org.junit.Assert {
    
    public AuthorityKeyIdentifierTest() {
        WSProviderConfig.init();
    }
    
    @org.junit.Test
    public void testExtractKeyIdentifiers() throws Exception {
        // Load the keystore
        KeyStore keyStore = loadKeyStore("keys/wss40.jks", "security");
        assertNotNull(keyStore);
        
        X509Certificate cert = (X509Certificate)keyStore.getCertificate("wss40");
        assertNotNull(cert);
        
        // Get AuthorityKeyIdentifier from the cert
        byte[] keyIdentifierBytes = BouncyCastleUtils.getAuthorityKeyIdentifierBytes(cert);
        assertNotNull(keyIdentifierBytes);
        
        // Now load the CA cert
        KeyStore caKeyStore = loadKeyStore("keys/wss40CA.jks", "security");
        assertNotNull(caKeyStore);
        
        X509Certificate caCert = (X509Certificate)caKeyStore.getCertificate("wss40CA");
        assertNotNull(caCert);
        
        // Get SubjectKeyIdentifier from the CA cert
        byte[] subjectKeyIdentifierBytes = 
            BouncyCastleUtils.getSubjectKeyIdentifierBytes(caCert);
        assertNotNull(subjectKeyIdentifierBytes);

        assertTrue(Arrays.equals(keyIdentifierBytes, subjectKeyIdentifierBytes));
    }
    
    @org.junit.Test
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
        } catch (Exception ex) {
            // expected
        }
    }
    
    private KeyStore loadKeyStore(String path, String password) throws Exception {
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        ClassLoader loader = Loader.getClassLoader(AuthorityKeyIdentifierTest.class);
        InputStream input = Merlin.loadInputStream(loader, path);
        keyStore.load(input, password.toCharArray());
        input.close();

        return keyStore;
    }
}
