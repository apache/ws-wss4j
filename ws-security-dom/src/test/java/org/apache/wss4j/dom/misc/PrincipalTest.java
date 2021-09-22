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

import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.security.auth.callback.CallbackHandler;
import javax.xml.namespace.QName;

import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.crypto.CryptoType;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.principal.SAMLTokenPrincipal;
import org.apache.wss4j.common.principal.UsernameTokenPrincipal;
import org.apache.wss4j.common.saml.SAMLCallback;
import org.apache.wss4j.common.saml.SAMLUtil;
import org.apache.wss4j.common.saml.SamlAssertionWrapper;
import org.apache.wss4j.common.token.BinarySecurity;
import org.apache.wss4j.common.token.X509Security;
import org.apache.wss4j.common.util.SOAPUtil;
import org.apache.wss4j.common.util.XMLUtils;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.common.SAML1CallbackHandler;
import org.apache.wss4j.dom.common.SAML2CallbackHandler;

import org.apache.wss4j.dom.common.UsernamePasswordCallbackHandler;
import org.apache.wss4j.dom.engine.WSSConfig;
import org.apache.wss4j.dom.engine.WSSecurityEngine;
import org.apache.wss4j.dom.engine.WSSecurityEngineResult;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.handler.WSHandlerResult;
import org.apache.wss4j.dom.message.WSSecHeader;
import org.apache.wss4j.dom.message.WSSecSAMLToken;
import org.apache.wss4j.dom.message.WSSecUsernameToken;
import org.apache.wss4j.dom.util.WSSecurityUtil;
import org.apache.wss4j.dom.validate.Credential;
import org.apache.wss4j.dom.validate.Validator;

import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test various principal objects after processing a security token.
 */
public class PrincipalTest {
    private static final org.slf4j.Logger LOG =
        org.slf4j.LoggerFactory.getLogger(PrincipalTest.class);

    private CallbackHandler callbackHandler = new UsernamePasswordCallbackHandler();

    /**
     * Test the principal that is created after processing a Username Token
     */
    @Test
    public void testUsernameToken() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecUsernameToken builder = new WSSecUsernameToken(secHeader);
        builder.setUserInfo("wernerd", "verySecret");
        Document signedDoc = builder.build();

        if (LOG.isDebugEnabled()) {
            String outputString =
                XMLUtils.prettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        WSHandlerResult results = verify(signedDoc, null);

        Principal principal =
            (Principal)results.getResults().get(0).get(WSSecurityEngineResult.TAG_PRINCIPAL);
        assertTrue(principal instanceof UsernameTokenPrincipal);
        assertTrue("wernerd".equals(principal.getName()));
        UsernameTokenPrincipal userPrincipal = (UsernameTokenPrincipal)principal;
        assertNotNull(userPrincipal.getCreatedTime());
        assertNotNull(userPrincipal.getNonce());
        assertNotNull(userPrincipal.getPassword());
        assertTrue(userPrincipal.isPasswordDigest());
        assertTrue(WSConstants.PASSWORD_DIGEST.equals(userPrincipal.getPasswordType()));
    }

    /**
     * Test the principal that is created after processing a Username Token, which has been
     * transformed into a SAML Assertion.
     */
    @Test
    public void testTransformedUsernameToken() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecUsernameToken builder = new WSSecUsernameToken(secHeader);
        builder.setUserInfo("wernerd", "verySecret");
        Document signedDoc = builder.build();

        if (LOG.isDebugEnabled()) {
            String outputString =
                XMLUtils.prettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        WSHandlerResult results =
            verify(signedDoc, new DummyValidator(), WSConstants.USERNAME_TOKEN, null);

        Principal principal =
            (Principal)results.getResults().get(0).get(WSSecurityEngineResult.TAG_PRINCIPAL);
        assertTrue(principal instanceof SAMLTokenPrincipal);
        assertTrue(principal.getName().contains("uid=joe"));
        assertNotNull(((SAMLTokenPrincipal)principal).getToken());
    }

    /**
     * Test the principal that is created after processing a SAML Token
     */
    @Test
    public void testSAMLToken() throws Exception {
        SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
        callbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHN);
        callbackHandler.setIssuer("www.example.com");

        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
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

        WSHandlerResult results = verify(unsignedDoc, null);

        List<WSSecurityEngineResult> samlResults =
            results.getActionResults().get(WSConstants.ST_UNSIGNED);
        WSSecurityEngineResult actionResult = samlResults.get(0);

        SamlAssertionWrapper receivedSamlAssertion =
            (SamlAssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertNotNull(receivedSamlAssertion);

        Principal principal = (Principal)actionResult.get(WSSecurityEngineResult.TAG_PRINCIPAL);
        assertTrue(principal instanceof SAMLTokenPrincipal);
        assertTrue(principal.getName().contains("uid=joe"));
        assertNotNull(((SAMLTokenPrincipal)principal).getToken());
    }

    /**
     * Test the principal that is created after processing a SAML2 Token
     */
    @Test
    public void testSAML2Token() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
        callbackHandler.setIssuer("www.example.com");

        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
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

        WSHandlerResult results = verify(unsignedDoc, null);

        List<WSSecurityEngineResult> samlResults =
            results.getActionResults().get(WSConstants.ST_UNSIGNED);
        WSSecurityEngineResult actionResult = samlResults.get(0);

        SamlAssertionWrapper receivedSamlAssertion =
            (SamlAssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertNotNull(receivedSamlAssertion);

        Principal principal = (Principal)actionResult.get(WSSecurityEngineResult.TAG_PRINCIPAL);
        assertTrue(principal instanceof SAMLTokenPrincipal);
        assertTrue(principal.getName().contains("uid=joe"));
        assertNotNull(((SAMLTokenPrincipal)principal).getToken());
    }

    /**
     * Test the principal that is created after processing a SAML Token, which has been
     * transformed into another SAML Token.
     */
    @Test
    public void testTransformedSAMLToken() throws Exception {
        SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
        callbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHN);
        callbackHandler.setIssuer("www.example.com");

        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
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

        WSHandlerResult results =
            verify(unsignedDoc, new DummyValidator(), WSConstants.SAML_TOKEN, null);

        List<WSSecurityEngineResult> samlResults =
            results.getActionResults().get(WSConstants.ST_UNSIGNED);
        WSSecurityEngineResult actionResult = samlResults.get(0);

        SamlAssertionWrapper receivedSamlAssertion =
            (SamlAssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertNotNull(receivedSamlAssertion);

        Principal principal = (Principal)actionResult.get(WSSecurityEngineResult.TAG_PRINCIPAL);
        assertTrue(principal instanceof SAMLTokenPrincipal);
        assertTrue(principal.getName().contains("uid=joe"));
        assertNotNull(((SAMLTokenPrincipal)principal).getToken());
    }

    /**
     * Test the principal that is created after processing (and explicitly validating)
     * a BinarySecurityToken.
     */
    @Test
    public void testBinarySecurityToken() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);

        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        X509Security bst = new X509Security(doc);
        CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
        cryptoType.setAlias("wss40");
        Crypto crypto = CryptoFactory.getInstance("wss40.properties");
        X509Certificate[] certs = crypto.getX509Certificates(cryptoType);
        bst.setX509Certificate(certs[0]);

        WSSecurityUtil.prependChildElement(secHeader.getSecurityHeaderElement(), bst.getElement());

        if (LOG.isDebugEnabled()) {
            String outputString =
                XMLUtils.prettyDocumentToString(doc);
            LOG.debug(outputString);
        }

        WSHandlerResult results =
            verify(doc, new DummyValidator(), WSConstants.BINARY_TOKEN, crypto);

        List<WSSecurityEngineResult> bstResults =
            results.getActionResults().get(WSConstants.BST);
        WSSecurityEngineResult actionResult = bstResults.get(0);

        BinarySecurity token =
            (BinarySecurity)actionResult.get(WSSecurityEngineResult.TAG_BINARY_SECURITY_TOKEN);
        assertNotNull(token);

        Principal principal = (Principal)actionResult.get(WSSecurityEngineResult.TAG_PRINCIPAL);
        assertTrue(principal instanceof SAMLTokenPrincipal);
        assertTrue(principal.getName().contains("uid=joe"));
        assertNotNull(((SAMLTokenPrincipal)principal).getToken());
    }

    /**
     * Verifies the soap envelope
     */
    private WSHandlerResult verify(
        Document doc,
        Crypto crypto
    ) throws Exception {
        return verify(doc, null, null, crypto);
    }

    /**
     * Verifies the soap envelope
     */
    private WSHandlerResult verify(
        Document doc,
        Validator validator,
        QName validatorName,
        Crypto crypto
    ) throws Exception {
        RequestData requestData = new RequestData();
        requestData.setCallbackHandler(callbackHandler);
        requestData.setDecCrypto(crypto);
        requestData.setSigVerCrypto(crypto);
        requestData.setValidateSamlSubjectConfirmation(false);

        WSSecurityEngine secEngine = new WSSecurityEngine();
        WSSConfig config = WSSConfig.getNewInstance();
        secEngine.setWssConfig(config);

        if (validator != null && validatorName != null) {
            config.setValidator(validatorName, validator);
        }
        return secEngine.processSecurityHeader(doc, requestData);
    }

    /**
     * A Dummy Validator instance that just creates a new SAML Assertion, ignoring the
     * credential it has been passed.
     */
    private static class DummyValidator implements Validator {

        public Credential validate(Credential credential, RequestData data) throws WSSecurityException {
            try {
                SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
                callbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHN);
                callbackHandler.setIssuer("www.example.com");

                SAMLCallback samlCallback = new SAMLCallback();
                SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
                SamlAssertionWrapper samlAssertion = new SamlAssertionWrapper(samlCallback);

                credential.setTransformedToken(samlAssertion);
                return credential;
            } catch (Exception ex) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE);
            }
        }

    }
}