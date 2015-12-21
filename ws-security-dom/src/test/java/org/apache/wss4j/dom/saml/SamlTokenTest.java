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

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.Key;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.security.auth.callback.CallbackHandler;
import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.wss4j.common.bsp.BSPRule;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.crypto.CryptoType;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.saml.SAMLCallback;
import org.apache.wss4j.common.saml.SAMLUtil;
import org.apache.wss4j.common.saml.SamlAssertionWrapper;
import org.apache.wss4j.common.saml.bean.SubjectConfirmationDataBean;
import org.apache.wss4j.common.saml.builder.SAML1Constants;
import org.apache.wss4j.common.saml.builder.SAML2Constants;
import org.apache.wss4j.common.token.SecurityTokenReference;
import org.apache.wss4j.common.util.DOM2Writer;
import org.apache.wss4j.common.util.XMLUtils;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.common.CustomHandler;
import org.apache.wss4j.dom.common.CustomSamlAssertionValidator;
import org.apache.wss4j.dom.common.KeystoreCallbackHandler;
import org.apache.wss4j.dom.common.SAML1CallbackHandler;
import org.apache.wss4j.dom.common.SAML2CallbackHandler;
import org.apache.wss4j.dom.common.SAMLElementCallbackHandler;
import org.apache.wss4j.dom.common.SOAPUtil;
import org.apache.wss4j.dom.common.SecurityTestUtil;
import org.apache.wss4j.dom.engine.WSSConfig;
import org.apache.wss4j.dom.engine.WSSecurityEngine;
import org.apache.wss4j.dom.engine.WSSecurityEngineResult;
import org.apache.wss4j.dom.handler.HandlerAction;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.handler.WSHandlerConstants;
import org.apache.wss4j.dom.handler.WSHandlerResult;
import org.apache.wss4j.dom.message.WSSecHeader;
import org.apache.wss4j.dom.message.WSSecSAMLToken;
import org.apache.wss4j.dom.validate.SamlAssertionValidator;
import org.apache.xml.security.encryption.EncryptedData;
import org.apache.xml.security.encryption.EncryptedKey;
import org.apache.xml.security.encryption.Reference;
import org.apache.xml.security.encryption.ReferenceList;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.keys.content.RetrievalMethod;
import org.apache.xml.security.keys.content.X509Data;
import org.apache.xml.security.stax.impl.util.IDGenerator;
import org.joda.time.DateTime;
import org.junit.Test;
import org.opensaml.core.xml.XMLObjectBuilder;
import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.schema.XSAny;
import org.opensaml.core.xml.schema.XSInteger;
import org.opensaml.saml.common.SAMLObjectBuilder;
import org.opensaml.saml.saml2.core.AttributeValue;
import org.opensaml.saml.saml2.core.Conditions;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * Test-case for sending and processing an unsigned (sender vouches) SAML Assertion.
 */
public class SamlTokenTest extends org.junit.Assert {
    private static final org.slf4j.Logger LOG =
        org.slf4j.LoggerFactory.getLogger(SamlTokenTest.class);
    private WSSecurityEngine secEngine = new WSSecurityEngine();
    private static final String IP_ADDRESS = "12.34.56.78"; //NOPMD

    @org.junit.AfterClass
    public static void cleanup() throws Exception {
        SecurityTestUtil.cleanup();
    }

    public SamlTokenTest() {
        WSSConfig config = WSSConfig.getNewInstance();
        config.setValidator(WSConstants.SAML_TOKEN, new CustomSamlAssertionValidator());
        config.setValidator(WSConstants.SAML2_TOKEN, new CustomSamlAssertionValidator());
        secEngine.setWssConfig(config);
    }

    /**
     * Test that creates, sends and processes an unsigned SAML 1.1 authentication assertion.
     */
    @Test
    public void testSAML1AuthnAssertion() throws Exception {
        SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
        callbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHN);
        callbackHandler.setIssuer("www.example.com");

        WSHandlerResult results =
            createAndVerifyMessage(callbackHandler, true);
        WSSecurityEngineResult actionResult =
            results.getActionResults().get(WSConstants.ST_UNSIGNED).get(0);

        SamlAssertionWrapper receivedSamlAssertion =
            (SamlAssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedSamlAssertion != null);
        assertFalse(receivedSamlAssertion.isSigned());
        assertTrue(receivedSamlAssertion.getSignatureValue() == null);
    }

    /**
     * Test that creates, sends and processes an unsigned SAML 1.1 authentication assertion.
     * It set a DOM Element on the CallbackHandler rather than creating a set of beans for
     * SamlAssertionWrapper to parse.
     */
    @Test
    public void testSAML1AuthnAssertionViaElement() throws Exception {
        SAMLElementCallbackHandler callbackHandler = new SAMLElementCallbackHandler();
        callbackHandler.setIssuer("www.example.com");

        WSHandlerResult results =
            createAndVerifyMessage(callbackHandler, true);
        WSSecurityEngineResult actionResult =
            results.getActionResults().get(WSConstants.ST_UNSIGNED).get(0);

        SamlAssertionWrapper receivedSamlAssertion =
            (SamlAssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedSamlAssertion != null);
        assertFalse(receivedSamlAssertion.isSigned());
        assertTrue(receivedSamlAssertion.getSignatureValue() == null);
    }

    /**
     * Test that creates, sends and processes an unsigned SAML 1.1 attribute assertion.
     */
    @Test
    public void testSAML1AttrAssertion() throws Exception {
        SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
        callbackHandler.setStatement(SAML1CallbackHandler.Statement.ATTR);
        callbackHandler.setIssuer("www.example.com");

        WSHandlerResult results =
            createAndVerifyMessage(callbackHandler, true);
        WSSecurityEngineResult actionResult =
            results.getActionResults().get(WSConstants.ST_UNSIGNED).get(0);

        SamlAssertionWrapper receivedSamlAssertion =
            (SamlAssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedSamlAssertion != null);
        assertFalse(receivedSamlAssertion.isSigned());
    }

    /**
     * Test that creates, sends and processes an unsigned SAML 1.1 authorization assertion.
     */
    @Test
    public void testSAML1AuthzAssertion() throws Exception {
        SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
        callbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHZ);
        callbackHandler.setIssuer("www.example.com");
        callbackHandler.setResource("http://resource.org");

        WSHandlerResult results =
            createAndVerifyMessage(callbackHandler, true);
        WSSecurityEngineResult actionResult =
            results.getActionResults().get(WSConstants.ST_UNSIGNED).get(0);

        SamlAssertionWrapper receivedSamlAssertion =
            (SamlAssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedSamlAssertion != null);
        assertFalse(receivedSamlAssertion.isSigned());
    }

    /**
     * Test that creates, sends and processes an unsigned SAML 2 authentication assertion.
     */
    @Test
    public void testSAML2AuthnAssertion() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
        callbackHandler.setIssuer("www.example.com");

        WSHandlerResult results =
            createAndVerifyMessage(callbackHandler, true);
        WSSecurityEngineResult actionResult =
            results.getActionResults().get(WSConstants.ST_UNSIGNED).get(0);

        SamlAssertionWrapper receivedSamlAssertion =
            (SamlAssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedSamlAssertion != null);
        assertFalse(receivedSamlAssertion.isSigned());
    }

    /**
     * Test that creates, sends and processes an unsigned SAML 2 attribute assertion.
     */
    @Test
    public void testSAML2AttrAssertion() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.ATTR);
        callbackHandler.setIssuer("www.example.com");

        WSHandlerResult results =
            createAndVerifyMessage(callbackHandler, true);
        WSSecurityEngineResult actionResult =
            results.getActionResults().get(WSConstants.ST_UNSIGNED).get(0);

        SamlAssertionWrapper receivedSamlAssertion =
            (SamlAssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedSamlAssertion != null);
        assertFalse(receivedSamlAssertion.isSigned());
    }

    /**
     * Test that creates, sends and processes an unsigned SAML 2 authorization assertion.
     */
    @Test
    public void testSAML2AuthzAssertion() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHZ);
        callbackHandler.setIssuer("www.example.com");
        callbackHandler.setResource("http://resource.org");

        WSHandlerResult results =
            createAndVerifyMessage(callbackHandler, true);
        WSSecurityEngineResult actionResult =
            results.getActionResults().get(WSConstants.ST_UNSIGNED).get(0);

        SamlAssertionWrapper receivedSamlAssertion =
            (SamlAssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedSamlAssertion != null);
        assertFalse(receivedSamlAssertion.isSigned());
    }

    /**
     * This test checks that an unsigned SAML1 sender-vouches authentication assertion
     * can be created by the WSHandler implementation
     */
    @Test
    public void testSaml1Action() throws Exception {
        final WSSConfig cfg = WSSConfig.getNewInstance();
        final RequestData reqData = new RequestData();
        reqData.setWssConfig(cfg);
        java.util.Map<String, Object> config = new java.util.TreeMap<String, Object>();
        config.put(WSHandlerConstants.SAML_CALLBACK_REF, new SAML1CallbackHandler());
        reqData.setMsgContext(config);

        final Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        CustomHandler handler = new CustomHandler();
        HandlerAction action = new HandlerAction(WSConstants.ST_UNSIGNED);
        handler.send(
            doc,
            reqData,
            Collections.singletonList(action),
            true
        );
        String outputString =
            XMLUtils.PrettyDocumentToString(doc);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Unsigned SAML 1.1 authentication assertion via an Action:");
            LOG.debug(outputString);
        }
        assertFalse(outputString.contains("Signature"));

        WSHandlerResult results = verify(doc);
        WSSecurityEngineResult actionResult =
            results.getActionResults().get(WSConstants.ST_UNSIGNED).get(0);

        SamlAssertionWrapper receivedSamlAssertion =
            (SamlAssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedSamlAssertion != null);
        assertFalse(receivedSamlAssertion.isSigned());
    }

    /**
     * Test that creates, sends and processes an unsigned SAML 1.1 authentication assertion.
     * The issuer is different from what the custom Validator is expecting, so it throws an
     * exception.
     */
    @Test
    public void testSAML1AuthnBadIssuerAssertion() throws Exception {
        SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
        callbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHN);
        callbackHandler.setIssuer("www.example2.com");

        createAndVerifyMessage(callbackHandler, false);
    }

    /**
     * Test that creates, sends and processes an unsigned SAML 2 authentication assertion.
     * The issuer is different from what the custom Validator is expecting, so it throws an
     * exception.
     */
    @Test
    public void testSAML2AuthnBadIssuerAssertion() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
        callbackHandler.setIssuer("www.example2.com");

        createAndVerifyMessage(callbackHandler, false);
    }

    /**
     * Test that creates, sends and processes an unsigned SAML 1.1 authentication assertion with
     * a user-specified SubjectNameIDFormat.
     */
    @Test
    public void testSAML1SubjectNameIDFormat() throws Exception {
        SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
        callbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHN);
        callbackHandler.setIssuer("www.example.com");
        callbackHandler.setSubjectNameIDFormat(SAML1Constants.NAMEID_FORMAT_EMAIL_ADDRESS);

        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper samlAssertion = new SamlAssertionWrapper(samlCallback);

        WSSecSAMLToken wsSign = new WSSecSAMLToken();

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        Document unsignedDoc = wsSign.build(doc, samlAssertion, secHeader);

        String outputString =
            XMLUtils.PrettyDocumentToString(unsignedDoc);
        if (LOG.isDebugEnabled()) {
            LOG.debug("SAML 1.1 Authn Assertion (sender vouches):");
            LOG.debug(outputString);
        }
        assertTrue(outputString.contains(SAML1Constants.NAMEID_FORMAT_EMAIL_ADDRESS));

        WSHandlerResult results = verify(unsignedDoc);
        WSSecurityEngineResult actionResult =
            results.getActionResults().get(WSConstants.ST_UNSIGNED).get(0);

        SamlAssertionWrapper receivedSamlAssertion =
            (SamlAssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedSamlAssertion != null);
        assertFalse(receivedSamlAssertion.isSigned());
    }

    /**
     * Test that creates, sends and processes an unsigned SAML 2 authentication assertion with
     * a user-specified SubjectNameIDFormat.
     */
    @Test
    public void testSAML2SubjectNameIDFormat() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
        callbackHandler.setIssuer("www.example.com");
        callbackHandler.setSubjectNameIDFormat(SAML1Constants.NAMEID_FORMAT_EMAIL_ADDRESS);

        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper samlAssertion = new SamlAssertionWrapper(samlCallback);

        WSSecSAMLToken wsSign = new WSSecSAMLToken();

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        Document unsignedDoc = wsSign.build(doc, samlAssertion, secHeader);

        String outputString =
            XMLUtils.PrettyDocumentToString(unsignedDoc);
        if (LOG.isDebugEnabled()) {
            LOG.debug("SAML 2 Authn Assertion (sender vouches):");
            LOG.debug(outputString);
        }
        assertTrue(outputString.contains(SAML1Constants.NAMEID_FORMAT_EMAIL_ADDRESS));

        WSHandlerResult results = verify(unsignedDoc);
        WSSecurityEngineResult actionResult =
            results.getActionResults().get(WSConstants.ST_UNSIGNED).get(0);

        SamlAssertionWrapper receivedSamlAssertion =
            (SamlAssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedSamlAssertion != null);
        assertFalse(receivedSamlAssertion.isSigned());
    }

    /**
     * Test that creates, sends and processes an unsigned SAML 1.1 authentication assertion with
     * a user-specified SubjectLocality statement.
     */
    @Test
    public void testSAML1SubjectLocality() throws Exception {
        SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
        callbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHN);
        callbackHandler.setIssuer("www.example.com");
        callbackHandler.setSubjectLocality(IP_ADDRESS, "test-dns");

        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper samlAssertion = new SamlAssertionWrapper(samlCallback);

        WSSecSAMLToken wsSign = new WSSecSAMLToken();

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        Document unsignedDoc = wsSign.build(doc, samlAssertion, secHeader);

        String outputString =
            XMLUtils.PrettyDocumentToString(unsignedDoc);
        if (LOG.isDebugEnabled()) {
            LOG.debug("SAML 1.1 Authn Assertion (sender vouches):");
            LOG.debug(outputString);
        }
        assertTrue(outputString.contains(IP_ADDRESS));
        assertTrue(outputString.contains("test-dns"));

        WSHandlerResult results = verify(unsignedDoc);
        WSSecurityEngineResult actionResult =
            results.getActionResults().get(WSConstants.ST_UNSIGNED).get(0);

        SamlAssertionWrapper receivedSamlAssertion =
            (SamlAssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedSamlAssertion != null);
        assertFalse(receivedSamlAssertion.isSigned());
    }

    /**
     * Test that creates, sends and processes an unsigned SAML 2.0 authentication assertion with
     * a user-specified SessionNotOnOrAfter DateTime.
     */
    @Test
    public void testSAML2SessionNotOnOrAfter() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHN);
        callbackHandler.setSessionNotOnOrAfter(new DateTime().plusHours(1));
        callbackHandler.setIssuer("www.example.com");

        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper samlAssertion = new SamlAssertionWrapper(samlCallback);

        WSSecSAMLToken wsSign = new WSSecSAMLToken();

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        Document unsignedDoc = wsSign.build(doc, samlAssertion, secHeader);

        String outputString =
            XMLUtils.PrettyDocumentToString(unsignedDoc);
        if (LOG.isDebugEnabled()) {
            LOG.debug("SAML 2.0 Authn Assertion (sender vouches):");
            LOG.debug(outputString);
        }
        assertTrue(outputString.contains("SessionNotOnOrAfter"));

        WSHandlerResult results = verify(unsignedDoc);
        WSSecurityEngineResult actionResult =
            results.getActionResults().get(WSConstants.ST_UNSIGNED).get(0);

        SamlAssertionWrapper receivedSamlAssertion =
            (SamlAssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedSamlAssertion != null);
        assertFalse(receivedSamlAssertion.isSigned());
    }

    /**
     * Test that creates, sends and processes an unsigned SAML 2 authentication assertion with
     * a user-specified SubjectLocality statement.
     */
    @Test
    public void testSAML2SubjectLocality() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
        callbackHandler.setIssuer("www.example.com");
        callbackHandler.setSubjectLocality(IP_ADDRESS, "test-dns");

        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper samlAssertion = new SamlAssertionWrapper(samlCallback);

        WSSecSAMLToken wsSign = new WSSecSAMLToken();

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        Document unsignedDoc = wsSign.build(doc, samlAssertion, secHeader);

        String outputString =
            XMLUtils.PrettyDocumentToString(unsignedDoc);
        if (LOG.isDebugEnabled()) {
            LOG.debug("SAML 2 Authn Assertion (sender vouches):");
            LOG.debug(outputString);
        }
        assertTrue(outputString.contains(IP_ADDRESS));
        assertTrue(outputString.contains("test-dns"));

        WSHandlerResult results = verify(unsignedDoc);
        WSSecurityEngineResult actionResult =
            results.getActionResults().get(WSConstants.ST_UNSIGNED).get(0);

        SamlAssertionWrapper receivedSamlAssertion =
            (SamlAssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedSamlAssertion != null);
        assertFalse(receivedSamlAssertion.isSigned());
    }

    /**
     * Test that creates, sends and processes an unsigned SAML 1.1 authorization assertion
     * with a Resource URI.
     */
    @Test
    public void testSAML1Resource() throws Exception {
        SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
        callbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHZ);
        callbackHandler.setIssuer("www.example.com");
        callbackHandler.setResource("http://resource.org");

        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper samlAssertion = new SamlAssertionWrapper(samlCallback);

        WSSecSAMLToken wsSign = new WSSecSAMLToken();

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        Document unsignedDoc = wsSign.build(doc, samlAssertion, secHeader);

        String outputString =
            XMLUtils.PrettyDocumentToString(unsignedDoc);
        if (LOG.isDebugEnabled()) {
            LOG.debug("SAML 1.1 Authz Assertion (sender vouches):");
            LOG.debug(outputString);
        }
        assertTrue(outputString.contains("http://resource.org"));

        WSHandlerResult results = verify(unsignedDoc);
        WSSecurityEngineResult actionResult =
            results.getActionResults().get(WSConstants.ST_UNSIGNED).get(0);

        SamlAssertionWrapper receivedSamlAssertion =
            (SamlAssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedSamlAssertion != null);
        assertFalse(receivedSamlAssertion.isSigned());
    }

    /**
     * Test that creates, sends and processes an unsigned SAML 2 attribute assertion. The attributeValue
     * has a custom XMLObject (not a String) value.
     */
    @Test
    @SuppressWarnings("unchecked")
    public void testSAML2AttrAssertionCustomAttribute() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.ATTR);
        callbackHandler.setIssuer("www.example.com");

        // Create and add a custom Attribute (conditions Object)
        XMLObjectBuilderFactory builderFactory =
            XMLObjectProviderRegistrySupport.getBuilderFactory();

        SAMLObjectBuilder<Conditions> conditionsV2Builder =
                (SAMLObjectBuilder<Conditions>)builderFactory.getBuilder(Conditions.DEFAULT_ELEMENT_NAME);
        Conditions conditions = conditionsV2Builder.buildObject();
        DateTime newNotBefore = new DateTime();
        conditions.setNotBefore(newNotBefore);
        conditions.setNotOnOrAfter(newNotBefore.plusMinutes(5));

        XMLObjectBuilder<XSAny> xsAnyBuilder =
            (XMLObjectBuilder<XSAny>)builderFactory.getBuilder(XSAny.TYPE_NAME);
        XSAny attributeValue = xsAnyBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME);
        attributeValue.getUnknownXMLObjects().add(conditions);

        List<Object> attributeValues = new ArrayList<>();
        attributeValues.add(attributeValue);
        callbackHandler.setCustomAttributeValues(attributeValues);

        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper samlAssertion = new SamlAssertionWrapper(samlCallback);

        WSSecSAMLToken wsSign = new WSSecSAMLToken();

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        Document unsignedDoc = wsSign.build(doc, samlAssertion, secHeader);

        if (LOG.isDebugEnabled()) {
            LOG.debug("SAML 2 Attr Assertion (sender vouches):");
            String outputString =
                XMLUtils.PrettyDocumentToString(unsignedDoc);
            LOG.debug(outputString);
        }

        WSHandlerResult results = verify(unsignedDoc);
        WSSecurityEngineResult actionResult =
            results.getActionResults().get(WSConstants.ST_UNSIGNED).get(0);

        SamlAssertionWrapper receivedSamlAssertion =
            (SamlAssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedSamlAssertion != null);
        assertFalse(receivedSamlAssertion.isSigned());
    }

    /**
     * Test that creates, sends and processes an unsigned SAML 2 attribute assertion. The attributeValue
     * has a custom XMLObject (xsd:type="xsd:int") value.
     */
    @Test
    @SuppressWarnings("unchecked")
    public void testSAML2AttrAssertionIntegerAttribute() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.ATTR);
        callbackHandler.setIssuer("www.example.com");

        // Create and add a custom Attribute (Integer)
        XMLObjectBuilderFactory builderFactory = XMLObjectProviderRegistrySupport.getBuilderFactory();

        XMLObjectBuilder<XSInteger> xsIntegerBuilder =
            (XMLObjectBuilder<XSInteger>)builderFactory.getBuilder(XSInteger.TYPE_NAME);
        XSInteger attributeValue =
            xsIntegerBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSInteger.TYPE_NAME);
        attributeValue.setValue(5);

        List<Object> attributeValues = new ArrayList<>();
        attributeValues.add(attributeValue);
        callbackHandler.setCustomAttributeValues(attributeValues);

        WSHandlerResult results = createAndVerifyMessage(callbackHandler, true);
        WSSecurityEngineResult actionResult =
            results.getActionResults().get(WSConstants.ST_UNSIGNED).get(0);

        SamlAssertionWrapper receivedSamlAssertion =
            (SamlAssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedSamlAssertion != null);
        assertFalse(receivedSamlAssertion.isSigned());
    }

    /**
     * Test that creates, sends and processes an unsigned SAML 2 authentication assertion with
     * SubjectConfirmationData information.
     */
    @Test
    public void testSAML2SubjectConfirmationData() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
        callbackHandler.setIssuer("www.example.com");

        SubjectConfirmationDataBean subjectConfirmationData = new SubjectConfirmationDataBean();
        subjectConfirmationData.setAddress("http://apache.org");
        subjectConfirmationData.setInResponseTo("12345");
        subjectConfirmationData.setNotAfter(new DateTime().plusMinutes(5));
        subjectConfirmationData.setRecipient("http://recipient.apache.org");
        callbackHandler.setSubjectConfirmationData(subjectConfirmationData);

        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper samlAssertion = new SamlAssertionWrapper(samlCallback);

        WSSecSAMLToken wsSign = new WSSecSAMLToken();

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        Document unsignedDoc = wsSign.build(doc, samlAssertion, secHeader);

        String outputString =
            XMLUtils.PrettyDocumentToString(unsignedDoc);
        if (LOG.isDebugEnabled()) {
            LOG.debug("SAML 2 Authn Assertion (sender vouches):");
            LOG.debug(outputString);
        }
        assertTrue(outputString.contains("http://recipient.apache.org"));

        WSHandlerResult results = createAndVerifyMessage(callbackHandler, true);
        WSSecurityEngineResult actionResult =
            results.getActionResults().get(WSConstants.ST_UNSIGNED).get(0);

        SamlAssertionWrapper receivedSamlAssertion =
            (SamlAssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedSamlAssertion != null);
        assertFalse(receivedSamlAssertion.isSigned());
    }

    /**
     * Test that creates, sends and processes an unsigned SAML 2 authentication assertion, which
     * is encrypted in a saml2:EncryptedAssertion Element in the security header
     */
    @Test
    public void testSAML2EncryptedAssertion() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
        callbackHandler.setIssuer("www.example.com");

        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper samlAssertion = new SamlAssertionWrapper(samlCallback);

        WSSecSAMLToken wsSign = new WSSecSAMLToken();

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        wsSign.prepare(doc, samlAssertion);

        // Get the Element + add it to the security header as an EncryptedAssertion
        Element assertionElement = wsSign.getElement();
        Element encryptedAssertionElement =
            doc.createElementNS(WSConstants.SAML2_NS, WSConstants.ENCRYPED_ASSERTION_LN);
        encryptedAssertionElement.appendChild(assertionElement);
        secHeader.getSecurityHeader().appendChild(encryptedAssertionElement);

        // Encrypt the Assertion
        KeyGenerator keygen = KeyGenerator.getInstance("AES");
        keygen.init(128);
        SecretKey secretKey = keygen.generateKey();
        Crypto crypto = CryptoFactory.getInstance("wss40.properties");
        CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
        cryptoType.setAlias("wss40");
        X509Certificate[] certs = crypto.getX509Certificates(cryptoType);
        assertTrue(certs != null && certs.length > 0 && certs[0] != null);

        encryptElement(doc, assertionElement, WSConstants.AES_128, secretKey,
                WSConstants.KEYTRANSPORT_RSAOEP, certs[0], false, true);

        if (LOG.isDebugEnabled()) {
            String outputString =
                XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }

        RequestData requestData = new RequestData();
        requestData.setValidateSamlSubjectConfirmation(false);
        requestData.setCallbackHandler(new KeystoreCallbackHandler());
        requestData.setDecCrypto(crypto);
        requestData.setSigVerCrypto(crypto);
        WSHandlerResult results = secEngine.processSecurityHeader(doc, requestData);

        WSSecurityEngineResult actionResult =
            results.getActionResults().get(WSConstants.ST_UNSIGNED).get(0);

        SamlAssertionWrapper receivedSamlAssertion =
            (SamlAssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedSamlAssertion != null);
        assertTrue(receivedSamlAssertion.getElement() != null);
        assertTrue("Assertion".equals(receivedSamlAssertion.getElement().getLocalName()));

        actionResult = results.getActionResults().get(WSConstants.ENCR).get(0);
        assertTrue(actionResult != null);
    }

    @Test
    public void testSAML2EncryptedAssertionViaSeparateEncryptedKey() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
        callbackHandler.setIssuer("www.example.com");

        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper samlAssertion = new SamlAssertionWrapper(samlCallback);

        WSSecSAMLToken wsSign = new WSSecSAMLToken();

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        wsSign.prepare(doc, samlAssertion);

        // Get the Element + add it to the security header as an EncryptedAssertion
        Element assertionElement = wsSign.getElement();
        Element encryptedAssertionElement =
            doc.createElementNS(WSConstants.SAML2_NS, WSConstants.ENCRYPED_ASSERTION_LN);
        encryptedAssertionElement.appendChild(assertionElement);
        secHeader.getSecurityHeader().appendChild(encryptedAssertionElement);

        // Encrypt the Assertion
        KeyGenerator keygen = KeyGenerator.getInstance("AES");
        keygen.init(128);
        SecretKey secretKey = keygen.generateKey();
        Crypto crypto = CryptoFactory.getInstance("wss40.properties");
        CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
        cryptoType.setAlias("wss40");
        X509Certificate[] certs = crypto.getX509Certificates(cryptoType);
        assertTrue(certs != null && certs.length > 0 && certs[0] != null);

        XMLCipher cipher = XMLCipher.getInstance(WSConstants.AES_128);
        cipher.init(XMLCipher.ENCRYPT_MODE, secretKey);

        // Create a KeyInfo for the EncryptedData
        EncryptedData builder = cipher.getEncryptedData();
        KeyInfo builderKeyInfo = builder.getKeyInfo();
        if (builderKeyInfo == null) {
            builderKeyInfo = new KeyInfo(doc);
            builderKeyInfo.getElement().setAttributeNS(
                "http://www.w3.org/2000/xmlns/", "xmlns:dsig",
                "http://www.w3.org/2000/09/xmldsig#"
            );
            builder.setKeyInfo(builderKeyInfo);
        }
        String encryptedKeyId = IDGenerator.generateID(null);
        RetrievalMethod retrievalMethod = new RetrievalMethod(doc, "#" + encryptedKeyId,
                                                              null, "http://www.w3.org/2001/04/xmlenc#EncryptedKey");
        builderKeyInfo.add(retrievalMethod);

        cipher.doFinal(doc, assertionElement, false);

        String id = IDGenerator.generateID(null);
        Element encryptedData =
            (Element)encryptedAssertionElement.getElementsByTagNameNS(WSConstants.ENC_NS, "EncryptedData").item(0);
        encryptedData.setAttributeNS(null, "Id", id);

        XMLCipher newCipher = XMLCipher.getInstance(WSConstants.KEYTRANSPORT_RSAOEP);
        newCipher.init(XMLCipher.WRAP_MODE, certs[0].getPublicKey());
        EncryptedKey encryptedKey = newCipher.encryptKey(doc, secretKey);

        KeyInfo encryptedKeyKeyInfo = encryptedKey.getKeyInfo();
        if (encryptedKeyKeyInfo == null) {
            encryptedKeyKeyInfo = new KeyInfo(doc);
            encryptedKeyKeyInfo.getElement().setAttributeNS(
                "http://www.w3.org/2000/xmlns/", "xmlns:dsig", "http://www.w3.org/2000/09/xmldsig#"
            );
            encryptedKey.setKeyInfo(encryptedKeyKeyInfo);
        }
        X509Data x509Data = new X509Data(doc);
        x509Data.addIssuerSerial(certs[0].getIssuerX500Principal().getName(),
                                 certs[0].getSerialNumber());
        encryptedKeyKeyInfo.add(x509Data);

        ReferenceList referenceList = newCipher.createReferenceList(ReferenceList.DATA_REFERENCE);
        Reference reference = referenceList.newDataReference("#" + id);
        referenceList.add(reference);
        encryptedKey.setReferenceList(referenceList);
        Element encryptedKeyElement = newCipher.martial(encryptedKey);
        encryptedKeyElement.setAttributeNS(null, "Id", encryptedKeyId);
        encryptedAssertionElement.appendChild(encryptedKeyElement);

        if (LOG.isDebugEnabled()) {
            String outputString =
                XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }

        RequestData requestData = new RequestData();
        requestData.setValidateSamlSubjectConfirmation(false);
        requestData.setCallbackHandler(new KeystoreCallbackHandler());
        requestData.setDecCrypto(crypto);
        requestData.setSigVerCrypto(crypto);
        requestData.setDisableBSPEnforcement(true);
        WSHandlerResult results = secEngine.processSecurityHeader(doc, requestData);

        WSSecurityEngineResult actionResult =
            results.getActionResults().get(WSConstants.ST_UNSIGNED).get(0);

        SamlAssertionWrapper receivedSamlAssertion =
            (SamlAssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedSamlAssertion != null);
        assertTrue(receivedSamlAssertion.getElement() != null);
        assertTrue("Assertion".equals(receivedSamlAssertion.getElement().getLocalName()));

        actionResult = results.getActionResults().get(WSConstants.ENCR).get(0);
        assertTrue(actionResult != null);
    }

    @Test
    public void testSAML2EncryptedAssertionNoSTR() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
        callbackHandler.setIssuer("www.example.com");

        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper samlAssertion = new SamlAssertionWrapper(samlCallback);

        WSSecSAMLToken wsSign = new WSSecSAMLToken();

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        wsSign.prepare(doc, samlAssertion);

        // Get the Element + add it to the security header as an EncryptedAssertion
        Element assertionElement = wsSign.getElement();
        Element encryptedAssertionElement =
            doc.createElementNS(WSConstants.SAML2_NS, WSConstants.ENCRYPED_ASSERTION_LN);
        encryptedAssertionElement.appendChild(assertionElement);
        secHeader.getSecurityHeader().appendChild(encryptedAssertionElement);

        // Encrypt the Assertion
        KeyGenerator keygen = KeyGenerator.getInstance("AES");
        keygen.init(128);
        SecretKey secretKey = keygen.generateKey();
        Crypto crypto = CryptoFactory.getInstance("wss40.properties");
        CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
        cryptoType.setAlias("wss40");
        X509Certificate[] certs = crypto.getX509Certificates(cryptoType);
        assertTrue(certs != null && certs.length > 0 && certs[0] != null);

        encryptElement(doc, assertionElement, WSConstants.AES_128, secretKey,
                WSConstants.KEYTRANSPORT_RSAOEP, certs[0], false, false);

        if (LOG.isDebugEnabled()) {
            String outputString =
                XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }

        RequestData data = new RequestData();
        data.setDecCrypto(crypto);
        List<BSPRule> ignoredRules = new ArrayList<>();
        ignoredRules.add(BSPRule.R5426);
        data.setIgnoredBSPRules(ignoredRules);
        data.setCallbackHandler(new KeystoreCallbackHandler());
        data.setValidateSamlSubjectConfirmation(false);

        WSSecurityEngine newEngine = new WSSecurityEngine();

        WSSConfig config = WSSConfig.getNewInstance();
        config.setValidator(WSConstants.SAML_TOKEN, new CustomSamlAssertionValidator());
        config.setValidator(WSConstants.SAML2_TOKEN, new CustomSamlAssertionValidator());
        newEngine.setWssConfig(config);

        WSHandlerResult results = newEngine.processSecurityHeader(doc, data);

        WSSecurityEngineResult actionResult =
            results.getActionResults().get(WSConstants.ST_UNSIGNED).get(0);

        SamlAssertionWrapper receivedSamlAssertion =
            (SamlAssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedSamlAssertion != null);
        assertTrue(receivedSamlAssertion.getElement() != null);
        assertTrue("Assertion".equals(receivedSamlAssertion.getElement().getLocalName()));

        actionResult = results.getActionResults().get(WSConstants.ENCR).get(0);
        assertTrue(actionResult != null);
    }

    @Test
    public void testAssertionWrapper() throws Exception {
        SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
        callbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHN);
        callbackHandler.setIssuer("www.example.com");

        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper samlAssertion = new SamlAssertionWrapper(samlCallback);

        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        Document doc = dbf.newDocumentBuilder().newDocument();
        String assertionString = DOM2Writer.nodeToString(samlAssertion.toDOM(doc));

        // Convert String to DOM + into an assertionWrapper
        InputStream in = new ByteArrayInputStream(assertionString.getBytes());
        Document newDoc = dbf.newDocumentBuilder().parse(in);

        SamlAssertionWrapper newAssertion =
            new SamlAssertionWrapper(newDoc.getDocumentElement());
        String secondAssertionString = newAssertion.assertionToString();
        assertEquals(assertionString, secondAssertionString);
    }

    @Test
    public void testAssertionWrapperNoDocument() throws Exception {
        SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
        callbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHN);
        callbackHandler.setIssuer("www.example.com");

        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper samlAssertion = new SamlAssertionWrapper(samlCallback);

        String assertionString = DOM2Writer.nodeToString(samlAssertion.toDOM(null));

        // Convert String to DOM + into an assertionWrapper
        InputStream in = new ByteArrayInputStream(assertionString.getBytes());

        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        Document newDoc = dbf.newDocumentBuilder().parse(in);

        SamlAssertionWrapper newAssertion =
            new SamlAssertionWrapper(newDoc.getDocumentElement());
        String secondAssertionString = newAssertion.assertionToString();
        assertEquals(assertionString, secondAssertionString);
    }

    @Test
    public void testRequiredSubjectConfirmationMethod() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
        callbackHandler.setIssuer("www.example.com");

        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper samlAssertion = new SamlAssertionWrapper(samlCallback);

        WSSecSAMLToken wsSign = new WSSecSAMLToken();

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        Document unsignedDoc = wsSign.build(doc, samlAssertion, secHeader);

        WSSConfig config = WSSConfig.getNewInstance();
        SamlAssertionValidator assertionValidator = new SamlAssertionValidator();
        assertionValidator.setRequiredSubjectConfirmationMethod(SAML2Constants.CONF_SENDER_VOUCHES);
        config.setValidator(WSConstants.SAML_TOKEN, assertionValidator);
        config.setValidator(WSConstants.SAML2_TOKEN, assertionValidator);

        WSSecurityEngine newEngine = new WSSecurityEngine();
        newEngine.setWssConfig(config);
        RequestData requestData = new RequestData();
        requestData.setValidateSamlSubjectConfirmation(false);

        newEngine.processSecurityHeader(doc, requestData);

        // Now create a Bearer assertion
        callbackHandler.setConfirmationMethod(SAML2Constants.CONF_BEARER);

        samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        samlAssertion = new SamlAssertionWrapper(samlCallback);

        wsSign = new WSSecSAMLToken();

        doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        unsignedDoc = wsSign.build(doc, samlAssertion, secHeader);
        try {
            newEngine.processSecurityHeader(unsignedDoc, null, null, null);
            fail("Failure expected on an incorrect subject confirmation method");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.FAILURE);
        }
    }

    @Test
    public void testStandardSubjectConfirmationMethod() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
        callbackHandler.setIssuer("www.example.com");
        callbackHandler.setConfirmationMethod("urn:oasis:names:tc:SAML:2.0:cm:custom");

        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper samlAssertion = new SamlAssertionWrapper(samlCallback);

        WSSecSAMLToken wsSign = new WSSecSAMLToken();

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        Document unsignedDoc = wsSign.build(doc, samlAssertion, secHeader);

        WSSecurityEngine newEngine = new WSSecurityEngine();
        try {
            newEngine.processSecurityHeader(unsignedDoc, null, null, null);
            fail("Failure expected on an unknown subject confirmation method");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.FAILURE);
        }

        // Now disable this check
        WSSConfig config = WSSConfig.getNewInstance();
        SamlAssertionValidator assertionValidator = new SamlAssertionValidator();
        assertionValidator.setRequireStandardSubjectConfirmationMethod(false);
        config.setValidator(WSConstants.SAML_TOKEN, assertionValidator);
        config.setValidator(WSConstants.SAML2_TOKEN, assertionValidator);

        newEngine.setWssConfig(config);

        RequestData requestData = new RequestData();
        requestData.setValidateSamlSubjectConfirmation(false);

        newEngine.processSecurityHeader(doc, requestData);
    }

    @Test
    public void testUnsignedBearer() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
        callbackHandler.setIssuer("www.example.com");
        callbackHandler.setConfirmationMethod(SAML2Constants.CONF_BEARER);

        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper samlAssertion = new SamlAssertionWrapper(samlCallback);

        WSSecSAMLToken wsSign = new WSSecSAMLToken();

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        Document unsignedDoc = wsSign.build(doc, samlAssertion, secHeader);

        WSSecurityEngine newEngine = new WSSecurityEngine();
        try {
            newEngine.processSecurityHeader(unsignedDoc, null, null, null);
            fail("Failure expected on an unsigned bearer token");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.FAILURE);
        }

        // Now disable this check
        WSSConfig config = WSSConfig.getNewInstance();
        SamlAssertionValidator assertionValidator = new SamlAssertionValidator();
        assertionValidator.setRequireBearerSignature(false);
        config.setValidator(WSConstants.SAML_TOKEN, assertionValidator);
        config.setValidator(WSConstants.SAML2_TOKEN, assertionValidator);

        newEngine.setWssConfig(config);

        RequestData requestData = new RequestData();
        requestData.setValidateSamlSubjectConfirmation(false);

        newEngine.processSecurityHeader(doc, requestData);
    }

    @Test
    public void testSAML2Advice() throws Exception {
        // Create a "Advice" Element first
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
        callbackHandler.setIssuer("www.example.com");

        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper samlAssertion = new SamlAssertionWrapper(samlCallback);

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        Element adviceElement = samlAssertion.toDOM(doc);

        // Now create a SAML Assertion that uses the advice Element
        callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
        callbackHandler.setIssuer("www.example.com");
        callbackHandler.setAssertionAdviceElement(adviceElement);

        samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        samlAssertion = new SamlAssertionWrapper(samlCallback);

        WSSecSAMLToken wsSign = new WSSecSAMLToken();

        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        Document unsignedDoc = wsSign.build(doc, samlAssertion, secHeader);

        String outputString =
            XMLUtils.PrettyDocumentToString(unsignedDoc);
        if (LOG.isDebugEnabled()) {
            LOG.debug(outputString);
        }
        assertTrue(outputString.contains("Advice"));

        WSHandlerResult results = verify(unsignedDoc);
        WSSecurityEngineResult actionResult =
            results.getActionResults().get(WSConstants.ST_UNSIGNED).get(0);

        SamlAssertionWrapper receivedSamlAssertion =
            (SamlAssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedSamlAssertion != null);
        assertFalse(receivedSamlAssertion.isSigned());
    }

    @Test
    public void testSAML2SpecialCharacter() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.ATTR);
        callbackHandler.setIssuer("www.example.com");
        // Test an "umlaut"
        String newSubjectName = "uid=j\u00f6e,ou=people,ou=saml-demo,o=example.com";
        callbackHandler.setSubjectName(newSubjectName);
        List<Object> customAttributeValue = new ArrayList<>(1);
        customAttributeValue.add("j\u00f6an");
        callbackHandler.setCustomAttributeValues(customAttributeValue);

        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper samlAssertion = new SamlAssertionWrapper(samlCallback);

        WSSecSAMLToken wsSign = new WSSecSAMLToken();

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        Document unsignedDoc = wsSign.build(doc, samlAssertion, secHeader);

        String outputString = XMLUtils.PrettyDocumentToString(unsignedDoc);
        // assertTrue(outputString.contains("j\u00f6e") && outputString.contains("j\u00f6an"));
        if (LOG.isDebugEnabled()) {
            LOG.debug(outputString);
        }

        RequestData requestData = new RequestData();
        requestData.setValidateSamlSubjectConfirmation(false);

        WSSecurityEngine newEngine = new WSSecurityEngine();
        WSHandlerResult results = newEngine.processSecurityHeader(doc, requestData);

        WSSecurityEngineResult actionResult =
            results.getActionResults().get(WSConstants.ST_UNSIGNED).get(0);

        SamlAssertionWrapper receivedSamlAssertion =
            (SamlAssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedSamlAssertion != null);
        assertFalse(receivedSamlAssertion.isSigned());
    }

    @Test
    public void testSAML2IssuerFormat() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
        callbackHandler.setIssuer("www.example.com");
        callbackHandler.setIssuerFormat("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent");

        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper samlAssertion = new SamlAssertionWrapper(samlCallback);

        WSSecSAMLToken wsSign = new WSSecSAMLToken();

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        Document unsignedDoc = wsSign.build(doc, samlAssertion, secHeader);

        String outputString =
            XMLUtils.PrettyDocumentToString(unsignedDoc);
        if (LOG.isDebugEnabled()) {
            LOG.debug(outputString);
        }
        assertTrue(outputString.contains("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"));

        WSHandlerResult results = createAndVerifyMessage(callbackHandler, true);
        WSSecurityEngineResult actionResult =
            results.getActionResults().get(WSConstants.ST_UNSIGNED).get(0);

        SamlAssertionWrapper receivedSamlAssertion =
            (SamlAssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedSamlAssertion != null);
        assertFalse(receivedSamlAssertion.isSigned());
    }

    private void encryptElement(
        Document document,
        Element elementToEncrypt,
        String algorithm,
        Key encryptingKey,
        String keyTransportAlgorithm,
        X509Certificate wrappingCert,
        boolean content,
        boolean useSecurityTokenReference
    ) throws Exception {
        XMLCipher cipher = XMLCipher.getInstance(algorithm);
        cipher.init(XMLCipher.ENCRYPT_MODE, encryptingKey);

        if (wrappingCert != null) {
            XMLCipher newCipher = XMLCipher.getInstance(keyTransportAlgorithm);
            newCipher.init(XMLCipher.WRAP_MODE, wrappingCert.getPublicKey());

            EncryptedKey encryptedKey = newCipher.encryptKey(document, encryptingKey);
            // Create a KeyInfo for the EncryptedKey
            KeyInfo encryptedKeyKeyInfo = encryptedKey.getKeyInfo();
            if (encryptedKeyKeyInfo == null) {
                encryptedKeyKeyInfo = new KeyInfo(document);
                encryptedKeyKeyInfo.getElement().setAttributeNS(
                    "http://www.w3.org/2000/xmlns/", "xmlns:dsig", "http://www.w3.org/2000/09/xmldsig#"
                );
                encryptedKey.setKeyInfo(encryptedKeyKeyInfo);
            }

            if (useSecurityTokenReference) {
                SecurityTokenReference securityTokenReference = new SecurityTokenReference(document);
                securityTokenReference.addWSSENamespace();
                securityTokenReference.setKeyIdentifierSKI(wrappingCert, null);
                encryptedKeyKeyInfo.addUnknownElement(securityTokenReference.getElement());
            } else {
                X509Data x509Data = new X509Data(document);
                // x509Data.addCertificate(wrappingCert);
                x509Data.addIssuerSerial(wrappingCert.getIssuerX500Principal().getName(),
                                         wrappingCert.getSerialNumber());
                encryptedKeyKeyInfo.add(x509Data);
            }

            // Create a KeyInfo for the EncryptedData
            EncryptedData builder = cipher.getEncryptedData();
            KeyInfo builderKeyInfo = builder.getKeyInfo();
            if (builderKeyInfo == null) {
                builderKeyInfo = new KeyInfo(document);
                builderKeyInfo.getElement().setAttributeNS(
                    "http://www.w3.org/2000/xmlns/", "xmlns:dsig", "http://www.w3.org/2000/09/xmldsig#"
                );
                builder.setKeyInfo(builderKeyInfo);
            }

            builderKeyInfo.add(encryptedKey);
        }

        cipher.doFinal(document, elementToEncrypt, content);
    }

    private WSHandlerResult createAndVerifyMessage(
        CallbackHandler samlCallbackHandler, boolean success
    ) throws Exception {
        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(samlCallbackHandler, samlCallback);
        SamlAssertionWrapper samlAssertion = new SamlAssertionWrapper(samlCallback);

        WSSecSAMLToken wsSign = new WSSecSAMLToken();

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        Document unsignedDoc = wsSign.build(doc, samlAssertion, secHeader);

        if (LOG.isDebugEnabled()) {
            String outputString =
                XMLUtils.PrettyDocumentToString(unsignedDoc);
            LOG.debug(outputString);
        }

        try {
            WSHandlerResult results = verify(unsignedDoc);
            if (!success) {
                fail("Failure expected in processing the SAML assertion");
            }
            return results;
        } catch (WSSecurityException ex) {
            assertFalse(success);
            assertTrue(ex.getMessage().contains("SAML token security failure"));
            return null;
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
                XMLUtils.PrettyDocumentToString(doc);
        assertTrue(outputString.indexOf("counter_port_type") > 0 ? true : false);
        return results;
    }

}
