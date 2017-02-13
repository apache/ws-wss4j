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

package org.apache.wss4j.dom.misc;

import java.io.IOException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.xml.namespace.QName;

import org.apache.wss4j.common.bsp.BSPEnforcer;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.ext.WSPasswordCallback;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.token.Reference;
import org.apache.wss4j.common.util.KeyUtils;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.common.SOAPUtil;
import org.apache.wss4j.dom.common.SecurityTestUtil;
import org.apache.wss4j.dom.engine.WSSConfig;
import org.apache.wss4j.dom.engine.WSSecurityEngine;
import org.apache.wss4j.dom.message.WSSecEncrypt;
import org.apache.wss4j.dom.message.WSSecHeader;
import org.apache.wss4j.dom.message.WSSecTimestamp;
import org.apache.wss4j.dom.message.WSSecUsernameToken;
import org.apache.wss4j.dom.message.token.UsernameToken;
import org.junit.Test;
import org.w3c.dom.Document;

/**
 * WS-Security Test Case for fault codes. The SOAP Message Security specification 1.1 defines
 * standard fault codes and fault strings for error propagation.
 */
public class FaultCodeTest extends org.junit.Assert implements CallbackHandler {
    private WSSecurityEngine secEngine = new WSSecurityEngine();
    private Crypto crypto = null;

    @org.junit.AfterClass
    public static void cleanup() throws Exception {
        SecurityTestUtil.cleanup();
    }

    public FaultCodeTest() throws Exception {
        crypto = CryptoFactory.getInstance("wss40.properties");
        WSSConfig.init();
    }

    /**
     * Test for the wsse:FailedCheck faultcode. This will fail due to a bad password in
     * the callback handler.
     */
    @Test
    public void testFailedCheck() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecEncrypt builder = new WSSecEncrypt(secHeader);
        builder.setUserInfo("wss40", "security");
        builder.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
        Document encryptedDoc = builder.build(crypto);

        try {
            verify(encryptedDoc);
            fail("Failure expected with a bad password");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.FAILED_CHECK);
            assertEquals("The private key for the supplied alias does not exist in the keystore", ex.getMessage());
            QName faultCode = new QName(WSConstants.WSSE_NS, "FailedCheck");
            assertTrue(ex.getFaultCode().equals(faultCode));
        }
    }

    /**
     * Test for the wsse:UnsupportedAlgorithm faultcode. This will fail due to the argument
     * passed to getCipherInstance.
     */
    @Test
    public void testUnsupportedAlgorithm() throws Exception {
        try {
            secEngine.getWssConfig();
            KeyUtils.getCipherInstance("Bad Algorithm");
            fail("Failure expected on an unsupported algorithm");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.UNSUPPORTED_ALGORITHM);
            assertEquals("unsupported key transport encryption algorithm: No such algorithm: \"Bad Algorithm\"", ex.getMessage());
            QName faultCode = new QName(WSConstants.WSSE_NS, "UnsupportedAlgorithm");
            assertTrue(ex.getFaultCode().equals(faultCode));
        }
    }

    /**
     * Test for the wsse:MessageExpired faultcode. This will fail due to the argument
     * passed to setTimeToLive.
     */
    @Test
    public void testMessageExpired() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecTimestamp builder = new WSSecTimestamp(secHeader);
        builder.setTimeToLive(-1);

        Document timestampedDoc = builder.build();

        try {
            verify(timestampedDoc);
            fail("Failure expected on an expired message");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.MESSAGE_EXPIRED);
            assertEquals("Invalid timestamp: The message timestamp has expired", ex.getMessage());
            QName faultCode = new QName(WSConstants.WSSE_NS, "MessageExpired");
            assertTrue(ex.getFaultCode().equals(faultCode));
        }
    }

    /**
     * Test for the wsse:FailedAuthentication faultcode. This will fail due to a bad password in
     * the callback handler.
     */
    @Test
    public void testFailedAuthentication() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecUsernameToken builder = new WSSecUsernameToken(secHeader);
        builder.addCreated();
        builder.addNonce();
        builder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");

        Document timestampedDoc = builder.build();

        try {
            verify(timestampedDoc);
            fail("Failure expected on a bad password");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.FAILED_AUTHENTICATION);
            assertEquals("The security token could not be authenticated or authorized", ex.getMessage());
            QName faultCode = new QName(WSConstants.WSSE_NS, "FailedAuthentication");
            assertTrue(ex.getFaultCode().equals(faultCode));
        }
    }

    /**
     * Test for the wsse:InvalidSecurityToken faultcode. This will fail due to the fact
     * that a null username is used.
     */
    @Test
    public void testInvalidSecurityToken() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecUsernameToken builder = new WSSecUsernameToken(secHeader);
        builder.addCreated();
        builder.addNonce();
        builder.setUserInfo(null, "security");

        builder.build();

        try {
            new UsernameToken(doc.getDocumentElement(), false, new BSPEnforcer());
            fail("Failure expected on an invalid security token");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.INVALID_SECURITY_TOKEN);
            assertEquals("Bad element, expected \"{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd}UsernameToken\" while got \"{http://schemas.xmlsoap.org/soap/envelope/}Envelope\"", ex.getMessage());
            QName faultCode = new QName(WSConstants.WSSE_NS, "InvalidSecurityToken");
            assertTrue(ex.getFaultCode().equals(faultCode));
        }
    }

    /**
     * Test for the wsse:InvalidSecurity faultcode.
     */
    @Test
    public void testInvalidSecurity() throws Exception {
        try {
            new Reference((org.w3c.dom.Element)null);
            fail("Failure expected on processing the security header");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.INVALID_SECURITY);
            assertEquals("<Reference> token could not be retrieved", ex.getMessage());
            QName faultCode = new QName(WSConstants.WSSE_NS, "InvalidSecurity");
            assertTrue(ex.getFaultCode().equals(faultCode));
        }
    }


    /**
     * Verifies the soap envelope.
     *
     * @param doc soap envelope
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
