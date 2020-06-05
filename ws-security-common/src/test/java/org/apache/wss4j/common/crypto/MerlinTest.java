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

import org.apache.wss4j.common.util.Loader;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.RepeatedTest;

import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Some tests for the Merlin Crypto provider
 */
public class MerlinTest {

    private static Merlin jksCrypto = new Merlin();
    private static Merlin pkcs12Crypto = new Merlin();

    @BeforeAll
    public static void setup() throws Exception {
        WSProviderConfig.init();
        KeyStore keyStore = loadKeyStore("keys/wss40.jks", "security");
        jksCrypto.setKeyStore(keyStore);

        KeyStore pkcs12KeyStore = loadKeyStore("keys/wss40.p12", "security");
        pkcs12Crypto.setKeyStore(pkcs12KeyStore);
    }

    @AfterAll
    public static void cleanup() {
        jksCrypto.clearCache();
        pkcs12Crypto.clearCache();
    }

    @RepeatedTest(1000)
    public void testGetPrivateKeyJKS() throws Exception {
        assertNotNull(jksCrypto.getPrivateKey("wss40", "security"));
    }

    @RepeatedTest(1000)
    public void testGetPrivateKeyPKCS12() throws Exception {
        assertNotNull(pkcs12Crypto.getPrivateKey("wss40", "security"));
    }

    @RepeatedTest(1000)
    public void testGetCertificateJKS() throws Exception {
        CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
        cryptoType.setAlias("wss40");
        assertNotNull(jksCrypto.getX509Certificates(cryptoType));
    }

    @RepeatedTest(1000)
    public void testGetCertificatePKCS12() throws Exception {
        CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
        cryptoType.setAlias("wss40");
        assertNotNull(pkcs12Crypto.getX509Certificates(cryptoType));
    }

    private static KeyStore loadKeyStore(String path, String password) throws Exception {
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        ClassLoader loader = Loader.getClassLoader(MerlinTest.class);
        InputStream input = Merlin.loadInputStream(loader, path);
        keyStore.load(input, password.toCharArray());
        input.close();

        return keyStore;
    }
}