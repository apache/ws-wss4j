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

package org.apache.wss4j.dom.saml;

import javax.security.auth.callback.CallbackHandler;

import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.saml.SAMLCallback;
import org.apache.wss4j.common.saml.SAMLUtil;
import org.apache.wss4j.common.saml.SamlAssertionWrapper;
import org.apache.wss4j.common.util.SOAPUtil;
import org.apache.wss4j.common.util.XMLUtils;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.common.CustomSamlAssertionValidator;
import org.apache.wss4j.dom.common.SAML1CallbackHandler;
import org.apache.wss4j.dom.common.SAML2CallbackHandler;

import org.apache.wss4j.dom.engine.WSSConfig;
import org.apache.wss4j.dom.engine.WSSecurityEngine;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.handler.WSHandlerResult;
import org.apache.wss4j.dom.message.WSSecHeader;
import org.apache.wss4j.dom.message.WSSecSAMLToken;
import org.joda.time.DateTime;

import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * Some tests for SAML Authentication Assertions
 */
public class SamlAuthnTest {
    private static final org.slf4j.Logger LOG =
        org.slf4j.LoggerFactory.getLogger(SamlAuthnTest.class);
    private WSSecurityEngine secEngine = new WSSecurityEngine();

    public SamlAuthnTest() {
        WSSConfig config = WSSConfig.getNewInstance();
        config.setValidator(WSConstants.SAML_TOKEN, new CustomSamlAssertionValidator());
        config.setValidator(WSConstants.SAML2_TOKEN, new CustomSamlAssertionValidator());
        secEngine.setWssConfig(config);
    }

    @Test
    public void testSAML1AuthnAssertion() throws Exception {
        SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
        callbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHN);
        callbackHandler.setIssuer("www.example.com");

        createAndVerifyMessage(callbackHandler, true);
    }

    @Test
    public void testSAML2AuthnAssertion() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHN);
        callbackHandler.setIssuer("www.example.com");

        createAndVerifyMessage(callbackHandler, true);
    }

    @Test
    public void testSAML1FutureAuthnInstant() throws Exception {
        SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
        callbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHN);
        callbackHandler.setIssuer("www.example.com");

        callbackHandler.setAuthenticationInstant(new DateTime().plusMinutes(70));

        createAndVerifyMessage(callbackHandler, false);
    }

    @Test
    public void testSAML2FutureAuthnInstant() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHN);
        callbackHandler.setIssuer("www.example.com");

        callbackHandler.setAuthenticationInstant(new DateTime().plusMinutes(70));

        createAndVerifyMessage(callbackHandler, false);
    }

    @Test
    public void testSAML2StaleSessionNotOnOrAfter() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHN);
        callbackHandler.setIssuer("www.example.com");

        callbackHandler.setSessionNotOnOrAfter(new DateTime().minusMinutes(70));

        createAndVerifyMessage(callbackHandler, false);
    }

    @Test
    public void testSAML1ValidSubjectLocality() throws Exception {
        SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
        callbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHN);
        callbackHandler.setIssuer("www.example.com");

        callbackHandler.setSubjectLocality("127.0.0.1", "xyz.ws.apache.org");   //NOPMD

        createAndVerifyMessage(callbackHandler, true);
    }

    @Test
    public void testSAML2ValidSubjectLocality() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHN);
        callbackHandler.setIssuer("www.example.com");

        callbackHandler.setSubjectLocality("127.0.0.1", "xyz.ws.apache.org");   //NOPMD

        createAndVerifyMessage(callbackHandler, true);
    }

    @Test
    public void testSAML1InvalidSubjectLocality() throws Exception {
        SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
        callbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHN);
        callbackHandler.setIssuer("www.example.com");

        callbackHandler.setSubjectLocality("xyz.ws.apache.org", "xyz.ws.apache.org");

        createAndVerifyMessage(callbackHandler, false);
    }

    @Test
    public void testSAML2InalidSubjectLocality() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHN);
        callbackHandler.setIssuer("www.example.com");

        callbackHandler.setSubjectLocality("xyz.ws.apache.org", "xyz.ws.apache.org");

        createAndVerifyMessage(callbackHandler, false);
    }

    private void createAndVerifyMessage(
        CallbackHandler samlCallbackHandler, boolean success
    ) throws Exception {
        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(samlCallbackHandler, samlCallback);
        SamlAssertionWrapper samlAssertion = new SamlAssertionWrapper(samlCallback);

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecSAMLToken wsSign = new WSSecSAMLToken(secHeader);

        Document unsignedDoc = wsSign.build(samlAssertion);

        if (LOG.isDebugEnabled()) {
            String outputString =
                XMLUtils.prettyDocumentToString(unsignedDoc);
            LOG.debug(outputString);
        }

        try {
            verify(unsignedDoc);
            if (!success) {
                fail("Failure expected in processing the SAML assertion");
            }
        } catch (WSSecurityException ex) {
            assertFalse(success);
            assertTrue(ex.getMessage().contains("SAML token security failure"));
        }
    }

    /**
     * Verifies the soap envelope
     * <p/>
     *
     * @param envelope
     * @throws Exception Thrown when there is a problem in verification
     */
    private WSHandlerResult verify(Document doc) throws Exception {
        RequestData requestData = new RequestData();
        requestData.setValidateSamlSubjectConfirmation(false);

        WSHandlerResult results = secEngine.processSecurityHeader(doc, requestData);
        String outputString =
            XMLUtils.prettyDocumentToString(doc);
        assertTrue(outputString.indexOf("counter_port_type") > 0 ? true : false);
        return results;
    }

}