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

package org.apache.wss4j.dom.message.token;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.security.auth.callback.CallbackHandler;

import org.apache.wss4j.common.bsp.BSPRule;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.util.XMLUtils;
import org.apache.wss4j.dom.common.SOAPUtil;
import org.apache.wss4j.dom.common.SecurityTestUtil;
import org.apache.wss4j.dom.common.UsernamePasswordCallbackHandler;
import org.apache.wss4j.dom.engine.WSSConfig;
import org.apache.wss4j.dom.engine.WSSecurityEngine;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.handler.WSHandlerResult;
import org.junit.Test;
import org.w3c.dom.Document;


/**
 * A test-case for WSS-199 - "Add support for WCF non-standard Username Tokens"
 * (see also WSS-148 - "WCF interop issue: Namespace not honored incase of attributes.").
 * The issue is that WCF generated Username Tokens where the password type is namespace
 * qualified (incorrectly). WSS-199 added the ability to process these Username Tokens.
 */
public class WCFUsernameTokenTest extends org.junit.Assert {
    private static final org.slf4j.Logger LOG =
        org.slf4j.LoggerFactory.getLogger(WCFUsernameTokenTest.class);
    private static final String SOAPUTMSG =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        + "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" "
        + "xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" "
        + "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">"
        + "<SOAP-ENV:Header>"
        + "<wsse:Security SOAP-ENV:mustUnderstand=\"1\" "
        + "xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\">"
        + "<wsse:UsernameToken wsu:Id=\"UsernameToken-29477163\" xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">"
        + "<wsse:Username>wernerd</wsse:Username>"
        + "<wsse:Password "
        + "wsse:Type=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText\">verySecret</wsse:Password>"
        + "</wsse:UsernameToken></wsse:Security></SOAP-ENV:Header>"
        + "<SOAP-ENV:Body>"
        + "<add xmlns=\"http://ws.apache.org/counter/counter_port_type\">"
        + "<value xmlns=\"\">15</value>" + "</add>"
        + "</SOAP-ENV:Body>\r\n       \r\n" + "</SOAP-ENV:Envelope>";

    private CallbackHandler callbackHandler = new UsernamePasswordCallbackHandler();

    @org.junit.AfterClass
    public static void cleanup() throws Exception {
        SecurityTestUtil.cleanup();
    }

    /**
     * Test that adds a UserNameToken with a namespace qualified type. This should fail
     * as WSS4J rejects these tokens by default.
     */
    @Test
    public void testNamespaceQualifiedTypeRejected() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUTMSG);

        if (LOG.isDebugEnabled()) {
            LOG.debug("Message with UserNameToken PW Digest:");
            String outputString =
                XMLUtils.prettyDocumentToString(doc);
            LOG.debug(outputString);
        }
        try {
            verify(doc);
            fail("Failure expected on a bad password type");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.INVALID_SECURITY);
        }
    }


    /**
     * Test that adds a UserNameToken with a namespace qualified type. This should pass
     * as WSS4J has been configured to accept these tokens.
     */
    @Test
    public void testNamespaceQualifiedTypeAccepted() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUTMSG);

        if (LOG.isDebugEnabled()) {
            LOG.debug("Message with UserNameToken PW Digest:");
            String outputString =
                XMLUtils.prettyDocumentToString(doc);
            LOG.debug(outputString);
        }

        RequestData requestData = new RequestData();
        requestData.setAllowNamespaceQualifiedPasswordTypes(true);
        requestData.setWssConfig(WSSConfig.getNewInstance());
        requestData.setIgnoredBSPRules(Collections.singletonList(BSPRule.R4201));
        verify(doc, requestData);
    }


    /**
     * Verifies the soap envelope
     */
    private WSHandlerResult verify(Document doc) throws Exception {
        return verify(doc, new ArrayList<BSPRule>(0));
    }

    /**
     * Verifies the soap envelope
     */
    private WSHandlerResult verify(
        Document doc, List<BSPRule> ignoredRules
    ) throws Exception {
        WSSecurityEngine secEngine = new WSSecurityEngine();
        RequestData requestData = new RequestData();
        requestData.setIgnoredBSPRules(ignoredRules);
        requestData.setCallbackHandler(callbackHandler);
        return secEngine.processSecurityHeader(doc, requestData);
    }

    /**
     * Verifies the soap envelope
     */
    private WSHandlerResult verify(
        Document doc, RequestData requestData
    ) throws Exception {
        WSSecurityEngine secEngine = new WSSecurityEngine();
        requestData.setCallbackHandler(callbackHandler);
        return secEngine.processSecurityHeader(doc, requestData);
    }


}
