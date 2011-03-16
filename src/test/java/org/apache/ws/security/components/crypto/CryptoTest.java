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

package org.apache.ws.security.components.crypto;

import java.io.InputStream;
import java.security.KeyStore;

import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.common.CustomCrypto;
import org.apache.ws.security.common.SOAPUtil;
import org.apache.ws.security.message.WSSecHeader;
import org.apache.ws.security.message.WSSecSignature;
import org.apache.ws.security.util.Loader;
import org.w3c.dom.Document;

public class CryptoTest extends org.junit.Assert {
    
    public CryptoTest() {
        WSSConfig.init();
    }
    
    @org.junit.Test
    public void testCrypto() throws Exception {
        Crypto crypto = CryptoFactory.getInstance();
        assertTrue(crypto != null);
    }

    @org.junit.Test
    public void testMerlinWithNullProperties() 
        throws Exception {
        Crypto crypto = new NullPropertiesCrypto();
        assertTrue(crypto != null);
    }
    
    /**
     * Ensure that we can load a custom crypto implementation using a Map
     */
    @org.junit.Test
    public void testCustomCrypto() throws Exception {
        java.util.Map<Object, Object> tmp = new java.util.TreeMap<Object, Object>();
        Crypto crypto = CryptoFactory.getInstance(
            org.apache.ws.security.common.CustomCrypto.class,
            tmp
        );
        assertNotNull(crypto);
        assertTrue(crypto instanceof CustomCrypto);
        CustomCrypto custom = (CustomCrypto)crypto;
        assertSame(tmp, custom.getConfig());
    }
    
    /**
     * Test for WSS-149 - "Merlin requires org.apache.ws.security.crypto.merlin.file
     * to be set and point to an existing file"
     */
    @org.junit.Test
    public void testNoKeyStoreFile() throws Exception {
        Crypto crypto = CryptoFactory.getInstance(
            "nofile.properties"
        );
        assertNotNull(crypto);
    }
    
    /**
     * Test that we can sign and verify a signature using dynamically loaded keystores/truststore
     */
    @org.junit.Test
    public void testDynamicCrypto() throws Exception {
        WSSecSignature builder = new WSSecSignature();
        builder.setUserInfo("wss40", "security");
        builder.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
        
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        // Load the keystore
        Crypto crypto = new Merlin();
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        ClassLoader loader = Loader.getClassLoader(CryptoTest.class);
        InputStream input = Merlin.loadInputStream(loader, "keys/wss40.jks");
        keyStore.load(input, "security".toCharArray());
        ((Merlin)crypto).setKeyStore(keyStore);
        Document signedDoc = builder.build(doc, crypto, secHeader);

        // Load the truststore
        Crypto processCrypto = new Merlin();
        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        input = Merlin.loadInputStream(loader, "keys/wss40CA.jks");
        trustStore.load(input, "security".toCharArray());
        ((Merlin)processCrypto).setTrustStore(trustStore);
        
        WSSecurityEngine secEngine = new WSSecurityEngine();
        secEngine.processSecurityHeader(signedDoc, null, null, processCrypto);
        
        // Load a (bad) truststore
        processCrypto = new Merlin();
        trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        input = Merlin.loadInputStream(loader, "keys/wss40badca.jks");
        trustStore.load(input, "security".toCharArray());
        ((Merlin)processCrypto).setTrustStore(trustStore);
        
        try {
            secEngine.processSecurityHeader(signedDoc, null, null, processCrypto);
            fail("Expected failure on a bad trust store");
        } catch (WSSecurityException ex) {
            // expected
        }
    }
    
    /**
     * WSS-102 -- ensure Merlin will null properties
     * can be instantiated
     */
    private static class NullPropertiesCrypto extends Merlin {
        public NullPropertiesCrypto() 
            throws Exception {
            super((java.util.Properties) null);
        }
    }
}
