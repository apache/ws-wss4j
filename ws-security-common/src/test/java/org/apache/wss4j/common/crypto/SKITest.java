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
import java.security.Security;
import java.security.cert.X509Certificate;

import org.apache.wss4j.common.util.Loader;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;

/**
 * This is a test for WSS-300 - "SubjectKeyIdentifier (SKI) incorrectly calculated for 2048-bit RSA key".
 * The SKI value WSS4J generates for various key sizes is tested against the output from openssl, e.g.:
 *
 * openssl x509 -inform der -ocspid -in wss40_server.crt | grep 'Public key OCSP hash'
 * | perl -ne 'split; print pack("H*",$_[4])' | base64
 */
public class SKITest extends org.junit.Assert {

    @Test
    public void testRSA1024() throws Exception {
        // Load the keystore
        Crypto crypto = new Merlin();
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        ClassLoader loader = Loader.getClassLoader(SKITest.class);
        InputStream input = Merlin.loadInputStream(loader, "keys/wss40_server.jks");
        keyStore.load(input, "security".toCharArray());
        input.close();
        ((Merlin)crypto).setKeyStore(keyStore);

        CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
        cryptoType.setAlias("wss40_server");
        X509Certificate[] certs = crypto.getX509Certificates(cryptoType);
        assertTrue(certs != null && certs.length > 0);

        byte[] skiBytes = crypto.getSKIBytesFromCert(certs[0]);
        String knownBase64Encoding = "VPWiTCLlm0OwNWTwrnRTUF3qcIk=";
        assertTrue(knownBase64Encoding.equals(org.apache.xml.security.utils.XMLUtils.encodeToString(skiBytes)));
    }

    @Test
    public void testRSA2048() throws Exception {
        // Load the keystore
        Crypto crypto = new Merlin();
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        ClassLoader loader = Loader.getClassLoader(SKITest.class);
        InputStream input = Merlin.loadInputStream(loader, "keys/rsa2048.jks");
        keyStore.load(input, "password".toCharArray());
        input.close();
        ((Merlin)crypto).setKeyStore(keyStore);

        CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
        cryptoType.setAlias("test");
        X509Certificate[] certs = crypto.getX509Certificates(cryptoType);
        assertTrue(certs != null && certs.length > 0);

        byte[] skiBytes = crypto.getSKIBytesFromCert(certs[0]);
        String knownBase64Encoding = "tgkZUMZ461ZSA1nZkBu6E5GDxLM=";
        assertTrue(knownBase64Encoding.equals(org.apache.xml.security.utils.XMLUtils.encodeToString(skiBytes)));
    }

    @Test
    public void testBouncyCastlePKCS12() throws Exception {
        try {
            Security.addProvider(new BouncyCastleProvider());

            // Load the keystore
            Crypto crypto = CryptoFactory.getInstance("alice_bouncycastle.properties");
            assertNotNull(crypto);
        } finally {
            Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
        }
    }
}
