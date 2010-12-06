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

package org.apache.ws.security.message;

import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.common.SOAPUtil;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.w3c.dom.Document;


/**
 * This class tests for error messages that apply to certificates, e.g. when a bad
 * "username" is used for encryption or signature. See WSS-137.
 */
public class CertErrorTest extends org.junit.Assert {
    private static final String SOAPMSG = 
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" 
        + "<SOAP-ENV:Envelope "
        +   "xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" "
        +   "xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" "
        +   "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">" 
        +   "<SOAP-ENV:Body>" 
        +       "<add xmlns=\"http://ws.apache.org/counter/counter_port_type\">" 
        +           "<value xmlns=\"\">15</value>" 
        +       "</add>" 
        +   "</SOAP-ENV:Body>" 
        + "</SOAP-ENV:Envelope>";
    

    /**
     * Test for when a bad certificate is used for Signature
     */
    @org.junit.Test
    public void testX509Signature() throws Exception {
        WSSecSignature builder = new WSSecSignature();
        builder.setUserInfo("bob", "security");
        Document doc = SOAPUtil.toSOAPPart(SOAPMSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        try {
            builder.build(doc, CryptoFactory.getInstance(), secHeader);
            fail("Expected failure on a bad username");
        } catch (WSSecurityException ex) {
            String expectedError = "No certificates for user bob were found for signature";
            assertTrue(ex.getMessage().indexOf(expectedError) != -1);
        }
    }
    
    /**
     * Test for when a bad certificate is used for Encryption
     */
    @org.junit.Test
    public void testEncryption() throws Exception {
        WSSecEncrypt builder = new WSSecEncrypt();
        builder.setUserInfo("alice");
        Document doc = SOAPUtil.toSOAPPart(SOAPMSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        try {
            builder.build(doc, CryptoFactory.getInstance(), secHeader);
            fail("Expected failure on a bad username");
        } catch (WSSecurityException ex) {
            String expectedError = "No certificates for user alice were found for encryption";
            assertTrue(ex.getMessage().indexOf(expectedError) != -1);
        }
    }

}
