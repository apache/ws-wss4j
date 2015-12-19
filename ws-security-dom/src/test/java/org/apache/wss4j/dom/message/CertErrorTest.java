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

import org.apache.wss4j.dom.common.SOAPUtil;
import org.apache.wss4j.dom.common.SecurityTestUtil;
import org.apache.wss4j.dom.engine.WSSConfig;
import org.junit.Test;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.w3c.dom.Document;


/**
 * This class tests for error messages that apply to certificates, e.g. when a bad
 * "username" is used for encryption or signature. See WSS-137.
 */
public class CertErrorTest extends org.junit.Assert {

    @org.junit.AfterClass
    public static void cleanup() throws Exception {
        SecurityTestUtil.cleanup();
    }

    public CertErrorTest() {
        WSSConfig.init();
    }

    /**
     * Test for when a bad certificate is used for Signature
     */
    @Test
    public void testX509Signature() throws Exception {
        WSSecSignature builder = new WSSecSignature();
        builder.setUserInfo("bob", "security");
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();
        try {
            builder.build(doc, CryptoFactory.getInstance(), secHeader);
            fail("Expected failure on a bad username");
        } catch (WSSecurityException ex) {
            String expectedError = "No certificates for user bob were found for signature";
            assertTrue(ex.getMessage().contains(expectedError));
        }
    }

    /**
     * Test for when a bad certificate is used for Encryption
     */
    @Test
    public void testEncryption() throws Exception {
        WSSecEncrypt builder = new WSSecEncrypt();
        builder.setUserInfo("alice");
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();
        try {
            builder.build(doc, CryptoFactory.getInstance(), secHeader);
            fail("Expected failure on a bad username");
        } catch (WSSecurityException ex) {
            String expectedError = "No certificates for user alice were found for encryption";
            assertTrue(ex.getMessage().contains(expectedError));
        }
    }

}
