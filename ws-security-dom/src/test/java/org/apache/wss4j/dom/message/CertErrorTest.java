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

package org.apache.wss4j.dom.message;

import org.apache.wss4j.common.util.SOAPUtil;
import org.apache.wss4j.dom.WSConstants;

import org.apache.wss4j.dom.engine.WSSConfig;

import org.junit.jupiter.api.Test;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.util.KeyUtils;
import org.w3c.dom.Document;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;


/**
 * This class tests for error messages that apply to certificates, e.g. when a bad
 * "username" is used for encryption or signature. See WSS-137.
 */
public class CertErrorTest {

    public CertErrorTest() {
        WSSConfig.init();
    }

    /**
     * Test for when a bad certificate is used for Signature
     */
    @Test
    public void testX509Signature() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecSignature builder = new WSSecSignature(secHeader);
        builder.setUserInfo("bob", "security");
        try {
            builder.build(CryptoFactory.getInstance());
            fail("Expected failure on a bad username");
        } catch (WSSecurityException ex) {
            String expectedError = "No certificates for user \"bob\" were found for signature";
            assertTrue(ex.getMessage().contains(expectedError));
        }
    }

    /**
     * Test for when a bad certificate is used for Encryption
     */
    @Test
    public void testEncryption() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecEncrypt builder = new WSSecEncrypt(secHeader);
        builder.setUserInfo("alice");
        try {
            KeyGenerator keyGen = KeyUtils.getKeyGenerator(WSConstants.AES_128);
            SecretKey symmetricKey = keyGen.generateKey();

            builder.build(CryptoFactory.getInstance(), symmetricKey);
            fail("Expected failure on a bad username");
        } catch (WSSecurityException ex) {
            String expectedError = "No certificates for user \"alice\" were found for encryption";
            assertTrue(ex.getMessage().contains(expectedError));
        }
    }

}