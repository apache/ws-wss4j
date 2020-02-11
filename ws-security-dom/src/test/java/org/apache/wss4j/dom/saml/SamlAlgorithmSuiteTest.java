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

import javax.xml.crypto.dsig.CanonicalizationMethod;
import org.apache.wss4j.common.saml.SamlAssertionWrapper;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.apache.wss4j.common.crypto.AlgorithmSuite;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.common.SAML1CallbackHandler;
import org.apache.wss4j.dom.common.SOAPUtil;
import org.apache.wss4j.dom.common.SecurityTestUtil;
import org.apache.wss4j.dom.engine.WSSConfig;
import org.apache.wss4j.dom.engine.WSSecurityEngine;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.handler.WSHandlerResult;
import org.apache.wss4j.dom.message.WSSecHeader;
import org.apache.wss4j.dom.message.WSSecSAMLToken;
import org.apache.wss4j.common.saml.SAMLCallback;
import org.apache.wss4j.common.saml.SAMLUtil;
import org.apache.wss4j.common.saml.builder.SAML1Constants;
import org.apache.wss4j.common.util.XMLUtils;
import org.apache.wss4j.dom.util.WSSecurityUtil;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * A set of test-cases for signing and verifying SOAP requests containing a signed
 * SAML (HOK) assertion when specifying an AlgorithmSuite policy.
 */
public class SamlAlgorithmSuiteTest {
    private static final org.slf4j.Logger LOG =
        org.slf4j.LoggerFactory.getLogger(SamlAlgorithmSuiteTest.class);
    private Crypto crypto;

    @AfterAll
    public static void cleanup() throws Exception {
        SecurityTestUtil.cleanup();
    }

    public SamlAlgorithmSuiteTest() throws Exception {
        WSSConfig.init();
        crypto = CryptoFactory.getInstance("crypto.properties");
    }

    @Test
    public void testSignedSAML11Assertion() throws Exception {
        SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
        callbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHN);
        callbackHandler.setConfirmationMethod(SAML1Constants.CONF_HOLDER_KEY);
        callbackHandler.setIssuer("www.example.com");

        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper samlAssertion = new SamlAssertionWrapper(samlCallback);

        samlAssertion.signAssertion("16c73ab6-b892-458f-abf5-2f875f74882e", "security", crypto, false);


        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecSAMLToken wsSign = new WSSecSAMLToken(secHeader);
        Document signedDoc = wsSign.build(samlAssertion);

        if (LOG.isDebugEnabled()) {
            String outputString =
                XMLUtils.prettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }

        Element securityHeader = WSSecurityUtil.getSecurityHeader(signedDoc, null);
        AlgorithmSuite algorithmSuite = createAlgorithmSuite();

        verify(securityHeader, algorithmSuite, crypto);

        algorithmSuite.setMinimumAsymmetricKeyLength(1024);

        try {
            verify(securityHeader, algorithmSuite, crypto);
            fail("Expected failure as 512-bit keys are not allowed");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.INVALID_SECURITY);
        }
    }

    @Test
    public void testDSASignedSAML11Assertion() throws Exception {
        Crypto dsaCrypto = CryptoFactory.getInstance("wss40.properties");

        SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
        callbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHN);
        callbackHandler.setConfirmationMethod(SAML1Constants.CONF_HOLDER_KEY);
        callbackHandler.setIssuer("www.example.com");

        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper samlAssertion = new SamlAssertionWrapper(samlCallback);

        samlAssertion.signAssertion("wss40DSA", "security", dsaCrypto, false);

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecSAMLToken wsSign = new WSSecSAMLToken(secHeader);

        Document signedDoc = wsSign.build(samlAssertion);

        if (LOG.isDebugEnabled()) {
            String outputString =
                XMLUtils.prettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }

        Element securityHeader = WSSecurityUtil.getSecurityHeader(signedDoc, null);
        AlgorithmSuite algorithmSuite = createAlgorithmSuite();

        try {
            verify(securityHeader, algorithmSuite, dsaCrypto);
            fail("Expected failure as DSA is not allowed");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.INVALID_SECURITY);
        }

        algorithmSuite.addSignatureMethod(WSConstants.DSA);
        verify(securityHeader, algorithmSuite, dsaCrypto);
    }

    @Test
    public void testC14nMethod() throws Exception {
        SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
        callbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHN);
        callbackHandler.setConfirmationMethod(SAML1Constants.CONF_HOLDER_KEY);
        callbackHandler.setIssuer("www.example.com");

        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper samlAssertion = new SamlAssertionWrapper(samlCallback);

        samlAssertion.signAssertion(
            "16c73ab6-b892-458f-abf5-2f875f74882e", "security", crypto, false,
            WSConstants.C14N_EXCL_WITH_COMMENTS, WSConstants.RSA_SHA1);


        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecSAMLToken wsSign = new WSSecSAMLToken(secHeader);

        Document signedDoc = wsSign.build(samlAssertion);

        if (LOG.isDebugEnabled()) {
            String outputString =
                XMLUtils.prettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }

        Element securityHeader = WSSecurityUtil.getSecurityHeader(signedDoc, null);
        AlgorithmSuite algorithmSuite = createAlgorithmSuite();

        try {
            verify(securityHeader, algorithmSuite, crypto);
            fail("Expected failure as C14n algorithm is not allowed");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.INVALID_SECURITY);
        }

        algorithmSuite.addC14nAlgorithm(WSConstants.C14N_EXCL_WITH_COMMENTS);
        verify(securityHeader, algorithmSuite, crypto);
    }

    @Test
    public void signWithEcdsaAlgorithm() throws Exception {
        crypto = CryptoFactory.getInstance("wss40.properties");
        SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
        callbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHN);
        callbackHandler.setConfirmationMethod(SAML1Constants.CONF_HOLDER_KEY);
        callbackHandler.setIssuer("www.example.com");

        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper samlAssertion = new SamlAssertionWrapper(samlCallback);

        samlAssertion.signAssertion(
            "wss40ec", "security", crypto, false,
            CanonicalizationMethod.EXCLUSIVE, WSConstants.ECDSA_SHA256);


        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecSAMLToken wsSign = new WSSecSAMLToken(secHeader);

        Document signedDoc = wsSign.build(samlAssertion);

        if (LOG.isDebugEnabled()) {
            String outputString =
                XMLUtils.prettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }

        Element securityHeader = WSSecurityUtil.getSecurityHeader(signedDoc, null);
        AlgorithmSuite algorithmSuite = createAlgorithmSuite();

        try {
            verify(securityHeader, algorithmSuite, crypto);
            fail("Expected failure as C14n algorithm is not allowed");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.INVALID_SECURITY);
        }

        algorithmSuite.addSignatureMethod(WSConstants.ECDSA_SHA1);

        verify(securityHeader, algorithmSuite, crypto);
    }

    private AlgorithmSuite createAlgorithmSuite() {
        AlgorithmSuite algorithmSuite = new AlgorithmSuite();
        algorithmSuite.addSignatureMethod(WSConstants.RSA_SHA1);
        algorithmSuite.setMinimumAsymmetricKeyLength(512);
        algorithmSuite.addC14nAlgorithm(WSConstants.C14N_EXCL_OMIT_COMMENTS);
        algorithmSuite.addDigestAlgorithm(WSConstants.SHA1);

        return algorithmSuite;
    }

    private WSHandlerResult verify(
        Element securityHeader, AlgorithmSuite algorithmSuite, Crypto sigVerCrypto
    ) throws Exception {
        WSSecurityEngine secEngine = new WSSecurityEngine();
        RequestData data = new RequestData();
        data.setSigVerCrypto(sigVerCrypto);
        data.setSamlAlgorithmSuite(algorithmSuite);
        data.setValidateSamlSubjectConfirmation(false);

        return secEngine.processSecurityHeader(securityHeader, data);
    }


}