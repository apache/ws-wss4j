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
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;

/**
 * This is a test for extracting AuthorityKeyIdentifier/SubjectKeyIdentifier information from
 * the certs using BouncyCastle.
 */
public class AuthorityKeyIdentifierTest extends org.junit.Assert {
    
    @org.junit.Test
    public void testExtractKeyIdentifiers() throws Exception {
        // Load the keystore
        KeyStore keyStore = loadKeyStore("keys/wss40.jks", "security");
        assertNotNull(keyStore);
        
        X509Certificate cert = (X509Certificate)keyStore.getCertificate("wss40");
        assertNotNull(cert);
        
        // Get AuthorityKeyIdentifier from the cert
        byte[] octets = (ASN1OctetString.getInstance(cert.getExtensionValue("2.5.29.35")).getOctets());     
        AuthorityKeyIdentifier authorityKeyIdentifier = 
            AuthorityKeyIdentifier.getInstance(octets);
        byte[] keyIdentifierBytes = authorityKeyIdentifier.getKeyIdentifier();
        assertNotNull(keyIdentifierBytes);
        
        // Now load the CA cert
        KeyStore caKeyStore = loadKeyStore("keys/wss40CA.jks", "security");
        assertNotNull(caKeyStore);
        
        X509Certificate caCert = (X509Certificate)caKeyStore.getCertificate("wss40CA");
        assertNotNull(caCert);
        
        // Get SubjectKeyIdentifier from the CA cert
        byte[] subjectOctets = 
            (ASN1OctetString.getInstance(caCert.getExtensionValue("2.5.29.14")).getOctets());     
        SubjectKeyIdentifier subjectKeyIdentifier =
            SubjectKeyIdentifier.getInstance(subjectOctets);
        assertNotNull(subjectKeyIdentifier);
        byte[] subjectKeyIdentifierBytes = subjectKeyIdentifier.getKeyIdentifier();
        assertNotNull(subjectKeyIdentifierBytes);

        assertTrue(Arrays.equals(keyIdentifierBytes, subjectKeyIdentifierBytes));
    }
    
    private KeyStore loadKeyStore(String path, String password) throws Exception {
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        ClassLoader loader = Loader.getClassLoader(AuthorityKeyIdentifierTest.class);
        InputStream input = Merlin.loadInputStream(loader, path);
        keyStore.load(input, password.toCharArray());
        
        return keyStore;
    }
}
