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

package org.apache.wss4j.dom.saml.dom;

import java.nio.file.Path;

import org.apache.wss4j.common.cache.EHCacheReplayCache;
import org.apache.wss4j.common.util.SOAPUtil;
import org.apache.wss4j.api.dom.WSConstants;

import org.apache.wss4j.api.dom.engine.WSSConfig;
import org.apache.wss4j.dom.engine.WSSecurityEngine;
import org.apache.wss4j.common.cache.ReplayCache;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.api.dom.message.WSSecHeader;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.dom.saml.SAMLCallback;
import org.apache.wss4j.dom.saml.SAMLUtil;
import org.apache.wss4j.dom.saml.SamlAssertionWrapper;
import org.apache.wss4j.dom.saml.bean.ConditionsBean;
import org.apache.wss4j.dom.saml.builder.SAML2Constants;
import org.apache.wss4j.dom.saml.message.WSSecSAMLToken;
import org.apache.wss4j.common.util.XMLUtils;
import org.apache.wss4j.api.dom.RequestData;
import org.apache.wss4j.dom.handler.WSHandlerResult;
import org.apache.wss4j.dom.util.WSSecurityUtil;
import org.apache.wss4j.dom.saml.validate.SamlAssertionValidator;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * Some test-cases for replay attacks.
 */
public class ReplayTest {
    private static final org.slf4j.Logger LOG =
        org.slf4j.LoggerFactory.getLogger(ReplayTest.class);

    private Crypto crypto;

    @TempDir
    Path tempDir;

    public ReplayTest() throws Exception {
        crypto = CryptoFactory.getInstance();
    }

    private ReplayCache createCache(String key) throws WSSecurityException {
        return new EHCacheReplayCache(key, tempDir);
    }

    /**
     * Test that creates, sends and processes an unsigned SAML 2 authentication assertion. This
     * is just a sanity test to make sure that it is possible to send the SAML token twice, as
     * no "OneTimeUse" Element is defined there is no problem with replaying it.
     * with a OneTimeUse Element
     */
    @Test
    public void testEhCacheReplayedSAML2() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
        callbackHandler.setIssuer("www.example.com");
        callbackHandler.setConfirmationMethod(SAML2Constants.CONF_BEARER);

        ConditionsBean conditions = new ConditionsBean();
        conditions.setTokenPeriodMinutes(5);

        callbackHandler.setConditions(conditions);

        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper samlAssertion = new SamlAssertionWrapper(samlCallback);

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecSAMLToken wsSign = new WSSecSAMLToken(secHeader);

        Document unsignedDoc = wsSign.build(samlAssertion);

        if (LOG.isDebugEnabled()) {
            String outputString = XMLUtils.prettyDocumentToString(unsignedDoc);
            LOG.debug(outputString);
        }

        WSSConfig wssConfig = WSSConfig.getNewInstance();
        SamlAssertionValidator assertionValidator = new SamlAssertionValidator();
        assertionValidator.setRequireBearerSignature(false);
        wssConfig.setValidator(WSConstants.SAML_TOKEN, assertionValidator);
        wssConfig.setValidator(WSConstants.SAML2_TOKEN, assertionValidator);

        RequestData data = new RequestData();
        data.setWssConfig(wssConfig);
        data.setCallbackHandler(callbackHandler);
        ReplayCache replayCache = createCache("wss4j.saml.one.time.use.cache-");
        data.setSamlOneTimeUseReplayCache(replayCache);

        // Successfully verify SAML Token
        verify(unsignedDoc, wssConfig, data);

        // Now try again - this should work fine as well
        verify(unsignedDoc, wssConfig, data);

        replayCache.close();
    }

    /**
     * Test that creates, sends and processes an unsigned SAML 2 authentication assertion
     * with a OneTimeUse Element
     */
    @Test
    public void testEhCacheReplayedSAML2OneTimeUse() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
        callbackHandler.setIssuer("www.example.com");
        callbackHandler.setConfirmationMethod(SAML2Constants.CONF_BEARER);

        ConditionsBean conditions = new ConditionsBean();
        conditions.setTokenPeriodMinutes(5);
        conditions.setOneTimeUse(true);

        callbackHandler.setConditions(conditions);

        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper samlAssertion = new SamlAssertionWrapper(samlCallback);

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecSAMLToken wsSign = new WSSecSAMLToken(secHeader);

        Document unsignedDoc = wsSign.build(samlAssertion);

        String outputString =
            XMLUtils.prettyDocumentToString(unsignedDoc);
        assertTrue(outputString.contains("OneTimeUse"));
        if (LOG.isDebugEnabled()) {
            LOG.debug(outputString);
        }

        WSSConfig wssConfig = WSSConfig.getNewInstance();
        SamlAssertionValidator assertionValidator = new SamlAssertionValidator();
        assertionValidator.setRequireBearerSignature(false);
        wssConfig.setValidator(WSConstants.SAML_TOKEN, assertionValidator);
        wssConfig.setValidator(WSConstants.SAML2_TOKEN, assertionValidator);

        RequestData data = new RequestData();
        data.setWssConfig(wssConfig);
        data.setCallbackHandler(callbackHandler);
        ReplayCache replayCache = createCache("wss4j.saml.one.time.use.cache-");
        data.setSamlOneTimeUseReplayCache(replayCache);

        // Successfully verify SAML Token
        verify(unsignedDoc, wssConfig, data);

        // Now try again - a replay attack should be detected
        try {
            verify(unsignedDoc, wssConfig, data);
            fail("Expected failure on a replay attack");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.INVALID_SECURITY);
        }

        replayCache.close();
    }

    /**
     * Verifies the soap envelope
     *
     * @param doc soap document
     * @param wssConfig
     * @throws Exception Thrown when there is a problem in verification
     */
    private WSHandlerResult verify(
        Document doc, WSSConfig wssConfig, RequestData data
    ) throws Exception {
        WSSecurityEngine secEngine = new WSSecurityEngine();
        secEngine.setWssConfig(wssConfig);
        Element elem = WSSecurityUtil.getSecurityHeader(doc, null);
        data.setSigVerCrypto(crypto);
        return secEngine.processSecurityHeader(elem, data);
    }


}