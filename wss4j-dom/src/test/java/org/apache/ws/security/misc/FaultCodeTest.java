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

package org.apache.ws.security.misc;

import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.WSPasswordCallback;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.common.SOAPUtil;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.ws.security.message.WSSecEncrypt;
import org.apache.ws.security.message.WSSecHeader;
import org.apache.ws.security.message.WSSecTimestamp;
import org.apache.ws.security.message.WSSecUsernameToken;
import org.apache.ws.security.message.token.Reference;
import org.apache.ws.security.message.token.UsernameToken;
import org.apache.ws.security.util.WSSecurityUtil;
import org.w3c.dom.Document;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.xml.namespace.QName;

import java.io.IOException;

/**
 * WS-Security Test Case for fault codes. The SOAP Message Security specification 1.1 defines
 * standard fault codes and fault strings for error propagation.
 */
public class FaultCodeTest extends org.junit.Assert implements CallbackHandler {
    private WSSecurityEngine secEngine = new WSSecurityEngine();
    private Crypto crypto = null;
    
    public FaultCodeTest() throws Exception {
        crypto = CryptoFactory.getInstance("wss40.properties");
    }

    /**
     * Test for the wsse:FailedCheck faultcode. This will fail due to a bad password in
     * the callback handler.
     */
    @org.junit.Test
    public void testFailedCheck() throws Exception {
        WSSecEncrypt builder = new WSSecEncrypt(secEngine.getWssConfig());
        builder.setUserInfo("wss40", "security");
        builder.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);        
        Document encryptedDoc = builder.build(doc, crypto, secHeader);
        
        try {
            verify(encryptedDoc);
            fail("Failure expected with a bad password");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == 6);
            assertTrue(ex.getMessage().startsWith("The signature or decryption was invalid"));
            QName faultCode = new QName(WSConstants.WSSE_NS, "FailedCheck");
            assertTrue(ex.getFaultCode().equals(faultCode));
        }
    }
    
    /**
     * Test for the wsse:UnsupportedAlgorithm faultcode. This will fail due to the argument
     * passed to getCipherInstance.
     */
    @org.junit.Test
    public void testUnsupportedAlgorithm() throws Exception {
        try {
            secEngine.getWssConfig();
            WSSecurityUtil.getCipherInstance("Bad Algorithm");
            fail("Failure expected on an unsupported algorithm");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == 2);
            assertTrue(ex.getMessage().startsWith(
                "An unsupported signature or encryption algorithm was used"));
            QName faultCode = new QName(WSConstants.WSSE_NS, "UnsupportedAlgorithm");
            assertTrue(ex.getFaultCode().equals(faultCode));
        }
    }
    
    /**
     * Test for the wsse:MessageExpired faultcode. This will fail due to the argument
     * passed to setTimeToLive.
     */
    @org.junit.Test
    public void testMessageExpired() throws Exception {
        WSSecTimestamp builder = new WSSecTimestamp(secEngine.getWssConfig());
        builder.setTimeToLive(-1);
        
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);        
        Document timestampedDoc = builder.build(doc, secHeader);
        
        try {
            verify(timestampedDoc);
            fail("Failure expected on an expired message");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == 8);
            assertTrue(ex.getMessage().startsWith(
                "The message has expired"));
            QName faultCode = new QName(WSConstants.WSSE_NS, "MessageExpired");
            assertTrue(ex.getFaultCode().equals(faultCode));
        }
    }
    
    /**
     * Test for the wsse:FailedAuthentication faultcode. This will fail due to a bad password in
     * the callback handler.
     */
    @org.junit.Test
    public void testFailedAuthentication() throws Exception {
        WSSecUsernameToken builder = new WSSecUsernameToken(secEngine.getWssConfig());
        builder.addCreated();
        builder.addNonce();
        builder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);        
        Document timestampedDoc = builder.build(doc, secHeader);
        
        try {
            verify(timestampedDoc);
            fail("Failure expected on a bad password");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == 5);
            assertTrue(ex.getMessage().startsWith(
                "The security token could not be authenticated or authorized"));
            QName faultCode = new QName(WSConstants.WSSE_NS, "FailedAuthentication");
            assertTrue(ex.getFaultCode().equals(faultCode));
        }
    }
    
    /**
     * Test for the wsse:InvalidSecurityToken faultcode. This will fail due to the fact
     * that a null username is used.
     */
    @org.junit.Test
    public void testInvalidSecurityToken() throws Exception {
        WSSecUsernameToken builder = new WSSecUsernameToken(secEngine.getWssConfig());
        builder.addCreated();
        builder.addNonce();
        builder.setUserInfo(null, "security");
        
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);        
        builder.build(doc, secHeader);
        
        try {
            new UsernameToken(doc.getDocumentElement());
            fail("Failure expected on an invalid security token");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == 4);
            assertTrue(ex.getMessage().startsWith(
                "An invalid security token was provided"));
            QName faultCode = new QName(WSConstants.WSSE_NS, "InvalidSecurityToken");
            assertTrue(ex.getFaultCode().equals(faultCode));
        }
    }
    
    /**
     * Test for the wsse:InvalidSecurity faultcode. 
     */
    @org.junit.Test
    public void testInvalidSecurity() throws Exception {
        try {
            new Reference((org.w3c.dom.Element)null);
            fail("Failure expected on processing the security header");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == 3);
            assertTrue(ex.getMessage().startsWith(
                "An error was discovered processing the <wsse:Security> header"));
            QName faultCode = new QName(WSConstants.WSSE_NS, "InvalidSecurity");
            assertTrue(ex.getFaultCode().equals(faultCode));
        }
    }
    
    
    /**
     * Verifies the soap envelope.
     * 
     * @param env soap envelope
     * @throws java.lang.Exception Thrown when there is a problem in verification
     */
    private void verify(Document doc) throws Exception {
        secEngine.processSecurityHeader(doc, null, this, crypto);
    }
    
    
    public void handle(Callback[] callbacks)
        throws IOException, UnsupportedCallbackException {
        for (int i = 0; i < callbacks.length; i++) {
            if (callbacks[i] instanceof WSPasswordCallback) {
                WSPasswordCallback pc = (WSPasswordCallback) callbacks[i];
                //
                // Deliberately wrong password
                //
                pc.setPassword("securit");
            } else {
                throw new UnsupportedCallbackException(callbacks[i], "Unrecognized Callback");
            }
        }
    }

}
