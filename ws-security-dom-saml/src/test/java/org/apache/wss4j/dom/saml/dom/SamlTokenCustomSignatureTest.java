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

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import org.apache.wss4j.api.dom.WSEncryptionPart;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.dom.saml.SAMLCallback;
import org.apache.wss4j.dom.saml.SAMLUtil;
import org.apache.wss4j.dom.saml.SamlAssertionWrapper;
import org.apache.wss4j.dom.saml.builder.SAML1Constants;
import org.apache.wss4j.common.util.SOAPUtil;
import org.apache.wss4j.common.util.XMLUtils;
import org.apache.wss4j.api.dom.WSConstants;
import org.apache.wss4j.common.crypto.KeystoreCallbackHandler;

import org.apache.wss4j.api.dom.engine.WSSConfig;
import org.apache.wss4j.dom.engine.WSSecurityEngine;
import org.apache.wss4j.dom.handler.HandlerAction;
import org.apache.wss4j.api.dom.RequestData;
import org.apache.wss4j.dom.handler.WSHandlerConstants;
import org.apache.wss4j.dom.handler.WSHandlerResult;
import org.apache.wss4j.api.dom.message.WSSecHeader;
import org.apache.wss4j.dom.message.WSSecSignature;

import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 */
public class SamlTokenCustomSignatureTest {
    private static final org.slf4j.Logger LOG =
        org.slf4j.LoggerFactory.getLogger(SamlTokenCustomSignatureTest.class);

    private Crypto crypto;

    public SamlTokenCustomSignatureTest() throws Exception {
        WSSConfig.init();
        crypto = CryptoFactory.getInstance("crypto.properties");
    }

    @Test
    public void testAddSAML1AndSign() throws Exception {
        SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
        callbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHN);
        callbackHandler.setConfirmationMethod(SAML1Constants.CONF_SENDER_VOUCHES);
        callbackHandler.setIssuer("www.example.com");

        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper samlAssertion = new SamlAssertionWrapper(samlCallback);

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        Element assertionElement = samlAssertion.toDOM(doc);

        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();
        secHeader.getSecurityHeaderElement().appendChild(assertionElement);

        WSSecSignature sign = new WSSecSignature(secHeader);
        sign.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        sign.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);

        WSEncryptionPart encP =
            new WSEncryptionPart(
                "Assertion",
                "urn:oasis:names:tc:SAML:1.0:assertion",
                "Element");
        encP.setRequired(false);
        sign.getParts().add(encP);

        Document signedDoc = sign.build(crypto);

        if (LOG.isDebugEnabled()) {
            String outputString = XMLUtils.prettyDocumentToString(doc);
            LOG.debug(outputString);
        }

        verify(signedDoc);
    }

    @Test
    public void testAddSAML1AndSignAction() throws Exception {
        SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
        callbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHN);
        callbackHandler.setConfirmationMethod(SAML1Constants.CONF_SENDER_VOUCHES);
        callbackHandler.setIssuer("www.example.com");

        final WSSConfig cfg = WSSConfig.getNewInstance();
        final RequestData reqData = new RequestData();
        reqData.setWssConfig(cfg);
        reqData.setUsername("16c73ab6-b892-458f-abf5-2f875f74882e");

        Map<String, Object> config = new TreeMap<>();
        config.put(WSHandlerConstants.SIG_PROP_FILE, "crypto.properties");
        config.put(WSHandlerConstants.SIG_KEY_ID, "DirectReference");
        config.put(
            WSHandlerConstants.SIGNATURE_PARTS,
            "{Element}{urn:oasis:names:tc:SAML:1.0:assertion}Assertion"
        );
        config.put(WSHandlerConstants.SAML_CALLBACK_REF, callbackHandler);
        config.put(WSHandlerConstants.PW_CALLBACK_REF, new KeystoreCallbackHandler());
        reqData.setMsgContext(config);

        final Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        CustomHandler handler = new CustomHandler();

        List<HandlerAction> actions = new ArrayList<>();
        HandlerAction action = new HandlerAction(WSConstants.ST_UNSIGNED);
        actions.add(action);
        action = new HandlerAction(WSConstants.SIGN);
        actions.add(action);

        handler.send(
            doc,
            reqData,
            actions,
            true
        );
        String outputString =
            XMLUtils.prettyDocumentToString(doc);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Signed message:");
            LOG.debug(outputString);
        }

        verify(doc);
    }

    /**
     * Verifies the soap envelope
     *
     * @param doc
     * @throws Exception Thrown when there is a problem in verification
     */
    private WSHandlerResult verify(Document doc) throws Exception {
        WSSecurityEngine secEngine = new WSSecurityEngine();
        RequestData requestData = new RequestData();
        requestData.setDecCrypto(crypto);
        requestData.setSigVerCrypto(crypto);
        requestData.setValidateSamlSubjectConfirmation(false);

        WSHandlerResult results = secEngine.processSecurityHeader(doc, requestData);
        String outputString = XMLUtils.prettyDocumentToString(doc);
        assertTrue(outputString.indexOf("counter_port_type") > 0 ? true : false);
        return results;
    }

}