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

package org.apache.wss4j.dom.components.crypto;

import java.io.InputStream;
import java.security.KeyStore;
import java.util.Properties;

import org.apache.wss4j.common.util.SOAPUtil;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.common.CustomCrypto;

import org.apache.wss4j.dom.engine.WSSConfig;
import org.apache.wss4j.dom.engine.WSSecurityEngine;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.crypto.Merlin;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.util.Loader;
import org.apache.wss4j.dom.message.WSSecHeader;
import org.apache.wss4j.dom.message.WSSecSignature;

import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class CryptoTest {

    public CryptoTest() {
        WSSConfig.init();
    }

    @Test
    public void testCrypto() throws Exception {
        Crypto crypto = CryptoFactory.getInstance();
        assertNotNull(crypto);
    }

    @Test
    public void testMerlinWithNullProperties()
        throws Exception {
        Crypto crypto = new NullPropertiesCrypto();
        assertNotNull(crypto);
    }

    /**
     * Ensure that we can load a custom crypto implementation using a Map
     */
    @Test
    public void testCustomCrypto() throws Exception {
        java.util.Map<Object, Object> tmp = new java.util.TreeMap<>();
        Crypto crypto = CryptoFactory.getInstance(
            CustomCrypto.class, tmp
        );
        assertNotNull(crypto);
        assertTrue(crypto instanceof CustomCrypto);
        CustomCrypto custom = (CustomCrypto)crypto;
        assertSame(tmp, custom.getConfig());
    }

    /**
     * Test for WSS-149 - "Merlin requires org.apache.wss4j.crypto.merlin.file
     * to be set and point to an existing file"
     */
    @Test
    public void testNoKeyStoreFile() throws Exception {
        Crypto crypto = CryptoFactory.getInstance(
            "nofile.properties"
        );
        assertNotNull(crypto);
    }

    /**
     * Test that we can sign and verify a signature using dynamically loaded keystores/truststore
     */
    @Test
    public void testDynamicCrypto() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecSignature builder = new WSSecSignature(secHeader);
        builder.setUserInfo("wss40", "security");
        builder.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);

        // Load the keystore
        Crypto crypto = new Merlin();
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        ClassLoader loader = Loader.getClassLoader(CryptoTest.class);
        InputStream input = Merlin.loadInputStream(loader, "keys/wss40.jks");
        keyStore.load(input, "security".toCharArray());
        input.close();
        ((Merlin)crypto).setKeyStore(keyStore);
        Document signedDoc = builder.build(crypto);

        // Load the truststore
        Crypto processCrypto = new Merlin();
        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        input = Merlin.loadInputStream(loader, "keys/wss40CA.jks");
        trustStore.load(input, "security".toCharArray());
        input.close();
        ((Merlin)processCrypto).setTrustStore(trustStore);

        WSSecurityEngine secEngine = new WSSecurityEngine();
        secEngine.processSecurityHeader(signedDoc, null, null, processCrypto);

        // Load a (bad) truststore
        processCrypto = new Merlin();
        trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        input = Merlin.loadInputStream(loader, "keys/wss40badca.jks");
        trustStore.load(input, "security".toCharArray());
        input.close();
        ((Merlin)processCrypto).setTrustStore(trustStore);

        try {
            secEngine.processSecurityHeader(signedDoc, null, null, processCrypto);
            fail("Expected failure on a bad trust store");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.FAILURE);
        }
    }

    @Test
    public void testCryptoFactoryMerlin() throws Exception {
        ClassLoader classLoader = this.getClass().getClassLoader();
        Properties properties = CryptoFactory.getProperties("crypto.properties", classLoader);
        Crypto crypto =
            CryptoFactory.getInstance(properties, classLoader, null);
        assertTrue(crypto instanceof Merlin);
    }

    @Test
    public void testCryptoFactoryMerlinDevice() throws Exception {
        ClassLoader classLoader = this.getClass().getClassLoader();
        Properties properties = CryptoFactory.getProperties("crypto_device.properties", classLoader);
        Crypto crypto =
            CryptoFactory.getInstance(properties, classLoader, null);
        assertTrue(crypto instanceof Merlin);
    }

    /**
     * WSS-102 -- ensure Merlin with null properties can be instantiated
     */
    private static class NullPropertiesCrypto extends Merlin {
        public NullPropertiesCrypto()
            throws Exception {
            super(null, null, null);
        }
    }
}