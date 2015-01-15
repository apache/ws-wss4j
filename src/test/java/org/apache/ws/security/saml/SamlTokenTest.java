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

package org.apache.ws.security.saml;

import java.security.Key;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;
import java.util.Properties;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.common.CustomHandler;
import org.apache.ws.security.common.CustomSamlAssertionValidator;
import org.apache.ws.security.common.KeystoreCallbackHandler;
import org.apache.ws.security.common.SAML1CallbackHandler;
import org.apache.ws.security.common.SAML2CallbackHandler;
import org.apache.ws.security.common.SAMLElementCallbackHandler;
import org.apache.ws.security.common.SOAPUtil;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.ws.security.components.crypto.CryptoType;
import org.apache.ws.security.handler.RequestData;
import org.apache.ws.security.handler.WSHandlerConstants;
import org.apache.ws.security.message.WSSecHeader;
import org.apache.ws.security.message.WSSecSAMLToken;
import org.apache.ws.security.message.token.SecurityTokenReference;
import org.apache.ws.security.saml.ext.AssertionWrapper;
import org.apache.ws.security.saml.ext.SAMLParms;
import org.apache.ws.security.saml.ext.bean.SubjectConfirmationDataBean;
import org.apache.ws.security.saml.ext.builder.SAML1Constants;
import org.apache.ws.security.saml.ext.builder.SAML2Constants;
import org.apache.ws.security.util.WSSecurityUtil;
import org.apache.ws.security.util.XMLUtils;
import org.apache.ws.security.validate.SamlAssertionValidator;
import org.apache.xml.security.encryption.EncryptedData;
import org.apache.xml.security.encryption.EncryptedKey;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.keys.KeyInfo;
import org.joda.time.DateTime;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.saml2.core.AttributeValue;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.XMLObjectBuilder;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.schema.XSAny;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * Test-case for sending and processing an unsigned (sender vouches) SAML Assertion.
 * 
 * @author Davanum Srinivas (dims@yahoo.com)
 */
public class SamlTokenTest extends org.junit.Assert {
    private static final org.apache.commons.logging.Log LOG = 
        org.apache.commons.logging.LogFactory.getLog(SamlTokenTest.class);
    private WSSecurityEngine secEngine = new WSSecurityEngine();

    public SamlTokenTest() {
        WSSConfig config = WSSConfig.getNewInstance();
        config.setValidator(WSSecurityEngine.SAML_TOKEN, new CustomSamlAssertionValidator());
        config.setValidator(WSSecurityEngine.SAML2_TOKEN, new CustomSamlAssertionValidator());
        secEngine.setWssConfig(config);
    }
    
    /**
     * Test that creates, sends and processes an unsigned SAML 1.1 authentication assertion.
     */
    @org.junit.Test
    public void testSAML1AuthnAssertion() throws Exception {
        SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
        callbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHN);
        callbackHandler.setIssuer("www.example.com");
        
        SAMLParms samlParms = new SAMLParms();
        samlParms.setCallbackHandler(callbackHandler);
        AssertionWrapper assertion = new AssertionWrapper(samlParms);

        WSSecSAMLToken wsSign = new WSSecSAMLToken();

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        Document unsignedDoc = wsSign.build(doc, assertion, secHeader);

        if (LOG.isDebugEnabled()) {
            LOG.debug("SAML 1.1 Authn Assertion (sender vouches):");
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(unsignedDoc);
            LOG.debug(outputString);
        }
        
        List<WSSecurityEngineResult> results = verify(unsignedDoc);
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.ST_UNSIGNED);
        AssertionWrapper receivedAssertion = 
            (AssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedAssertion != null);
        assertTrue(!receivedAssertion.isSigned());
        assertTrue(receivedAssertion.getSignatureValue() == null);
    }
    
    /**
     * Test that creates, sends and processes an unsigned SAML 1 authentication assertion, where
     * the configuration is loaded from a properties file
     */
    @org.junit.Test
    public void testSAML1AuthnAssertionFromProperties() throws Exception {
        SAMLIssuer saml = SAMLIssuerFactory.getInstance("saml_sv.properties");
        AssertionWrapper assertion = saml.newAssertion();

        WSSecSAMLToken wsSign = new WSSecSAMLToken();

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        Document unsignedDoc = wsSign.build(doc, assertion, secHeader);

        if (LOG.isDebugEnabled()) {
            LOG.debug("SAML 1.1 Authn Assertion (sender vouches):");
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(unsignedDoc);
            LOG.debug(outputString);
        }
        
        List<WSSecurityEngineResult> results = verify(unsignedDoc);
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.ST_UNSIGNED);
        AssertionWrapper receivedAssertion = 
            (AssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedAssertion != null);
        assertTrue(!receivedAssertion.isSigned());
    }
    
    /**
     * Test that creates, sends and processes an unsigned SAML 1.1 authentication assertion.
     * It set a DOM Element on the CallbackHandler rather than creating a set of beans for
     * AssertionWrapper to parse.
     */
    @org.junit.Test
    public void testSAML1AuthnAssertionViaElement() throws Exception {
        SAMLElementCallbackHandler callbackHandler = new SAMLElementCallbackHandler();
        callbackHandler.setIssuer("www.example.com");
        
        SAMLParms samlParms = new SAMLParms();
        samlParms.setCallbackHandler(callbackHandler);
        AssertionWrapper assertion = new AssertionWrapper(samlParms);

        WSSecSAMLToken wsSign = new WSSecSAMLToken();

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        Document unsignedDoc = wsSign.build(doc, assertion, secHeader);

        if (LOG.isDebugEnabled()) {
            LOG.debug("SAML 1.1 Authn Assertion (sender vouches - from an Element):");
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(unsignedDoc);
            LOG.debug(outputString);
        }
        
        List<WSSecurityEngineResult> results = verify(unsignedDoc);
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.ST_UNSIGNED);
        AssertionWrapper receivedAssertion = 
            (AssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedAssertion != null);
        assertTrue(!receivedAssertion.isSigned());
        assertTrue(receivedAssertion.getSignatureValue() == null);
    }
    
    /**
     * Test that creates, sends and processes an unsigned SAML 1.1 attribute assertion.
     */
    @org.junit.Test
    public void testSAML1AttrAssertion() throws Exception {
        SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
        callbackHandler.setStatement(SAML1CallbackHandler.Statement.ATTR);
        callbackHandler.setIssuer("www.example.com");
        
        SAMLParms samlParms = new SAMLParms();
        samlParms.setCallbackHandler(callbackHandler);
        AssertionWrapper assertion = new AssertionWrapper(samlParms);

        WSSecSAMLToken wsSign = new WSSecSAMLToken();

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        Document unsignedDoc = wsSign.build(doc, assertion, secHeader);

        if (LOG.isDebugEnabled()) {
            LOG.debug("SAML 1.1 Attr Assertion (sender vouches):");
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(unsignedDoc);
            LOG.debug(outputString);
        }
        
        List<WSSecurityEngineResult> results = verify(unsignedDoc);
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.ST_UNSIGNED);
        AssertionWrapper receivedAssertion = 
            (AssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedAssertion != null);
        assertTrue(!receivedAssertion.isSigned());
    }
    
    /**
     * Test that creates, sends and processes an unsigned SAML 1.1 authorization assertion.
     */
    @org.junit.Test
    public void testSAML1AuthzAssertion() throws Exception {
        SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
        callbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHZ);
        callbackHandler.setIssuer("www.example.com");
        callbackHandler.setResource("http://resource.org");
        
        SAMLParms samlParms = new SAMLParms();
        samlParms.setCallbackHandler(callbackHandler);
        AssertionWrapper assertion = new AssertionWrapper(samlParms);

        WSSecSAMLToken wsSign = new WSSecSAMLToken();

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        Document unsignedDoc = wsSign.build(doc, assertion, secHeader);

        if (LOG.isDebugEnabled()) {
            LOG.debug("SAML 1.1 Authz Assertion (sender vouches):");
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(unsignedDoc);
            LOG.debug(outputString);
        }
        
        List<WSSecurityEngineResult> results = verify(unsignedDoc);
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.ST_UNSIGNED);
        AssertionWrapper receivedAssertion = 
            (AssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedAssertion != null);
        assertTrue(!receivedAssertion.isSigned());
    }
    
    /**
     * Test that creates, sends and processes an unsigned SAML 2 authentication assertion.
     */
    @org.junit.Test
    public void testSAML2AuthnAssertion() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
        callbackHandler.setIssuer("www.example.com");
        
        SAMLParms samlParms = new SAMLParms();
        samlParms.setCallbackHandler(callbackHandler);
        AssertionWrapper assertion = new AssertionWrapper(samlParms);

        WSSecSAMLToken wsSign = new WSSecSAMLToken();

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        Document unsignedDoc = wsSign.build(doc, assertion, secHeader);

        if (LOG.isDebugEnabled()) {
            LOG.debug("SAML 2 Authn Assertion (sender vouches):");
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(unsignedDoc);
            LOG.debug(outputString);
        }
        
        List<WSSecurityEngineResult> results = verify(unsignedDoc);
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.ST_UNSIGNED);
        AssertionWrapper receivedAssertion = 
            (AssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedAssertion != null);
        assertTrue(!receivedAssertion.isSigned());
    }
    
    /**
     * Test that creates, sends and processes an unsigned SAML 2 attribute assertion.
     */
    @org.junit.Test
    public void testSAML2AttrAssertion() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.ATTR);
        callbackHandler.setIssuer("www.example.com");
        
        SAMLParms samlParms = new SAMLParms();
        samlParms.setCallbackHandler(callbackHandler);
        AssertionWrapper assertion = new AssertionWrapper(samlParms);

        WSSecSAMLToken wsSign = new WSSecSAMLToken();

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        Document unsignedDoc = wsSign.build(doc, assertion, secHeader);

        if (LOG.isDebugEnabled()) {
            LOG.debug("SAML 2 Attr Assertion (sender vouches):");
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(unsignedDoc);
            LOG.debug(outputString);
        }
        
        List<WSSecurityEngineResult> results = verify(unsignedDoc);
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.ST_UNSIGNED);
        AssertionWrapper receivedAssertion = 
            (AssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedAssertion != null);
        assertTrue(!receivedAssertion.isSigned());
    }
    
    /**
     * Test that creates, sends and processes an unsigned SAML 2 authorization assertion.
     */
    @org.junit.Test
    public void testSAML2AuthzAssertion() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHZ);
        callbackHandler.setIssuer("www.example.com");
        callbackHandler.setResource("http://resource.org");
        
        SAMLParms samlParms = new SAMLParms();
        samlParms.setCallbackHandler(callbackHandler);
        AssertionWrapper assertion = new AssertionWrapper(samlParms);

        WSSecSAMLToken wsSign = new WSSecSAMLToken();

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        Document unsignedDoc = wsSign.build(doc, assertion, secHeader);

        if (LOG.isDebugEnabled()) {
            LOG.debug("SAML 2 Authz Assertion (sender vouches):");
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(unsignedDoc);
            LOG.debug(outputString);
        }
        
        List<WSSecurityEngineResult> results = verify(unsignedDoc);
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.ST_UNSIGNED);
        AssertionWrapper receivedAssertion = 
            (AssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedAssertion != null);
        assertTrue(!receivedAssertion.isSigned());
    }

    /**
     * This test checks that an unsigned SAML1 sender-vouches authentication assertion
     * can be created by the WSHandler implementation 
     */
    @org.junit.Test
    public void testSaml1Action() throws Exception {
        final WSSConfig cfg = WSSConfig.getNewInstance();
        final int action = WSConstants.ST_UNSIGNED;
        final RequestData reqData = new RequestData();
        reqData.setWssConfig(cfg);
        java.util.Map<String, Object> config = new java.util.TreeMap<String, Object>();
        config.put(WSHandlerConstants.SAML_PROP_FILE, "saml_sv.properties");
        reqData.setMsgContext(config);
        
        final java.util.List<Integer> actions = new java.util.ArrayList<Integer>();
        actions.add(Integer.valueOf(action));
        final Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        CustomHandler handler = new CustomHandler();
        handler.send(
            action, 
            doc, 
            reqData, 
            actions,
            true
        );
        String outputString = 
            org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Unsigned SAML 1.1 authentication assertion via an Action:");
            LOG.debug(outputString);
        }
        assertFalse (outputString.contains("Signature"));
        
        List<WSSecurityEngineResult> results = verify(doc);
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.ST_UNSIGNED);
        AssertionWrapper receivedAssertion = 
            (AssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedAssertion != null);
        assertTrue(!receivedAssertion.isSigned());
    }
    
    /**
     * This test checks that an unsigned SAML1 sender-vouches authentication assertion
     * can be created by the WSHandler implementation 
     */
    @org.junit.Test
    public void testSaml1ActionRef() throws Exception {
        final WSSConfig cfg = WSSConfig.getNewInstance();
        final int action = WSConstants.ST_UNSIGNED;
        final RequestData reqData = new RequestData();
        reqData.setWssConfig(cfg);
        java.util.Map<String, Object> config = new java.util.TreeMap<String, Object>();
        
        Properties props = new Properties();
        props.put("org.apache.ws.security.saml.issuerClass", 
                  "org.apache.ws.security.saml.SAMLIssuerImpl");
        props.put("org.apache.ws.security.saml.issuer",
                  "www.example.com");
        props.put("org.apache.ws.security.saml.callback",
                  "org.apache.ws.security.common.SAML1CallbackHandler");
        
        config.put(WSHandlerConstants.SAML_PROP_REF_ID, "RefId-" + props.hashCode());
        reqData.setMsgContext(config);
        
        final java.util.List<Integer> actions = new java.util.ArrayList<Integer>();
        actions.add(Integer.valueOf(action));
        final Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        CustomHandler handler = new CustomHandler();
        handler.setProperty(config, "RefId-" + props.hashCode(), props);
        handler.send(
            action, 
            doc, 
            reqData, 
            actions,
            true
        );
        String outputString = 
            org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Unsigned SAML 1.1 authentication assertion via an Action:");
            LOG.debug(outputString);
        }
        assertFalse (outputString.contains("Signature"));
        
        List<WSSecurityEngineResult> results = verify(doc);
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.ST_UNSIGNED);
        AssertionWrapper receivedAssertion = 
            (AssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedAssertion != null);
        assertTrue(!receivedAssertion.isSigned());
    }
    
    /**
     * Test that creates, sends and processes an unsigned SAML 1.1 authentication assertion.
     * The issuer is different from what the custom Validator is expecting, so it throws an
     * exception.
     */
    @org.junit.Test
    public void testSAML1AuthnBadIssuerAssertion() throws Exception {
        SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
        callbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHN);
        callbackHandler.setIssuer("www.example2.com");
        
        SAMLParms samlParms = new SAMLParms();
        samlParms.setCallbackHandler(callbackHandler);
        AssertionWrapper assertion = new AssertionWrapper(samlParms);

        WSSecSAMLToken wsSign = new WSSecSAMLToken();

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        Document unsignedDoc = wsSign.build(doc, assertion, secHeader);

        if (LOG.isDebugEnabled()) {
            LOG.debug("SAML 1.1 Authn Assertion (sender vouches):");
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(unsignedDoc);
            LOG.debug(outputString);
        }
        
        try {
            verify(unsignedDoc);
            fail("Failure expected on a bad issuer");
        } catch (WSSecurityException ex) {
            // expected
        }
    }
    
    /**
     * Test that creates, sends and processes an unsigned SAML 2 authentication assertion.
     * The issuer is different from what the custom Validator is expecting, so it throws an
     * exception.
     */
    @org.junit.Test
    public void testSAML2AuthnBadIssuerAssertion() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
        callbackHandler.setIssuer("www.example2.com");
        
        SAMLParms samlParms = new SAMLParms();
        samlParms.setCallbackHandler(callbackHandler);
        AssertionWrapper assertion = new AssertionWrapper(samlParms);

        WSSecSAMLToken wsSign = new WSSecSAMLToken();

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        Document unsignedDoc = wsSign.build(doc, assertion, secHeader);

        if (LOG.isDebugEnabled()) {
            LOG.debug("SAML 2 Authn Assertion (sender vouches):");
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(unsignedDoc);
            LOG.debug(outputString);
        }
        
        try {
            verify(unsignedDoc);
            fail("Failure expected on a bad issuer");
        } catch (WSSecurityException ex) {
            // expected
        }
    }
    
    /**
     * Test that creates, sends and processes an unsigned SAML 1.1 authentication assertion with
     * a user-specified SubjectNameIDFormat.
     */
    @org.junit.Test
    public void testSAML1SubjectNameIDFormat() throws Exception {
        SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
        callbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHN);
        callbackHandler.setIssuer("www.example.com");
        callbackHandler.setSubjectNameIDFormat(SAML1Constants.NAMEID_FORMAT_EMAIL_ADDRESS);
        
        SAMLParms samlParms = new SAMLParms();
        samlParms.setCallbackHandler(callbackHandler);
        AssertionWrapper assertion = new AssertionWrapper(samlParms);

        WSSecSAMLToken wsSign = new WSSecSAMLToken();

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        Document unsignedDoc = wsSign.build(doc, assertion, secHeader);

        String outputString = 
            org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(unsignedDoc);
        if (LOG.isDebugEnabled()) {
            LOG.debug("SAML 1.1 Authn Assertion (sender vouches):");
            LOG.debug(outputString);
        }
        assertTrue(outputString.contains(SAML1Constants.NAMEID_FORMAT_EMAIL_ADDRESS));
        
        List<WSSecurityEngineResult> results = verify(unsignedDoc);
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.ST_UNSIGNED);
        AssertionWrapper receivedAssertion = 
            (AssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedAssertion != null);
        assertTrue(!receivedAssertion.isSigned());
    }
    
    /**
     * Test that creates, sends and processes an unsigned SAML 2 authentication assertion with
     * a user-specified SubjectNameIDFormat.
     */
    @org.junit.Test
    public void testSAML2SubjectNameIDFormat() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
        callbackHandler.setIssuer("www.example.com");
        callbackHandler.setSubjectNameIDFormat(SAML1Constants.NAMEID_FORMAT_EMAIL_ADDRESS);
        
        SAMLParms samlParms = new SAMLParms();
        samlParms.setCallbackHandler(callbackHandler);
        AssertionWrapper assertion = new AssertionWrapper(samlParms);

        WSSecSAMLToken wsSign = new WSSecSAMLToken();

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        Document unsignedDoc = wsSign.build(doc, assertion, secHeader);

        String outputString = 
            org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(unsignedDoc);
        if (LOG.isDebugEnabled()) {
            LOG.debug("SAML 2 Authn Assertion (sender vouches):");
            LOG.debug(outputString);
        }
        assertTrue(outputString.contains(SAML1Constants.NAMEID_FORMAT_EMAIL_ADDRESS));
        
        List<WSSecurityEngineResult> results = verify(unsignedDoc);
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.ST_UNSIGNED);
        AssertionWrapper receivedAssertion = 
            (AssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedAssertion != null);
        assertTrue(!receivedAssertion.isSigned());
    }
    
    /**
     * Test that creates, sends and processes an unsigned SAML 1.1 authentication assertion with
     * a user-specified SubjectLocality statement.
     */
    @org.junit.Test
    public void testSAML1SubjectLocality() throws Exception {
        SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
        callbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHN);
        callbackHandler.setIssuer("www.example.com");
        callbackHandler.setSubjectLocality("12.34.56.78", "test-dns");
        
        SAMLParms samlParms = new SAMLParms();
        samlParms.setCallbackHandler(callbackHandler);
        AssertionWrapper assertion = new AssertionWrapper(samlParms);

        WSSecSAMLToken wsSign = new WSSecSAMLToken();

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        Document unsignedDoc = wsSign.build(doc, assertion, secHeader);

        String outputString = 
            org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(unsignedDoc);
        if (LOG.isDebugEnabled()) {
            LOG.debug("SAML 1.1 Authn Assertion (sender vouches):");
            LOG.debug(outputString);
        }
        assertTrue(outputString.contains("12.34.56.78"));
        assertTrue(outputString.contains("test-dns"));
        
        List<WSSecurityEngineResult> results = verify(unsignedDoc);
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.ST_UNSIGNED);
        AssertionWrapper receivedAssertion = 
            (AssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedAssertion != null);
        assertTrue(!receivedAssertion.isSigned());
    }
    
    /**
     * Test that creates, sends and processes an unsigned SAML 2.0 authentication assertion with
     * a user-specified SessionNotOnOrAfter DateTime.
     */
    @org.junit.Test
    public void testSAML2SessionNotOnOrAfter() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHN);
        callbackHandler.setSessionNotOnOrAfter(new DateTime().plusHours(1));
        callbackHandler.setIssuer("www.example.com");
        
        SAMLParms samlParms = new SAMLParms();
        samlParms.setCallbackHandler(callbackHandler);
        AssertionWrapper assertion = new AssertionWrapper(samlParms);

        WSSecSAMLToken wsSign = new WSSecSAMLToken();

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        Document unsignedDoc = wsSign.build(doc, assertion, secHeader);

        String outputString = 
            org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(unsignedDoc);
        if (LOG.isDebugEnabled()) {
            LOG.debug("SAML 2.0 Authn Assertion (sender vouches):");
            LOG.debug(outputString);
        }
        assertTrue(outputString.contains("SessionNotOnOrAfter"));
        
        List<WSSecurityEngineResult> results = verify(unsignedDoc);
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.ST_UNSIGNED);
        AssertionWrapper receivedSamlAssertion =
            (AssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedSamlAssertion != null);
        assertFalse(receivedSamlAssertion.isSigned());
    }
    
    /**
     * Test that creates, sends and processes an unsigned SAML 2 authentication assertion with
     * a user-specified SubjectLocality statement.
     */
    @org.junit.Test
    public void testSAML2SubjectLocality() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
        callbackHandler.setIssuer("www.example.com");
        callbackHandler.setSubjectLocality("12.34.56.78", "test-dns");
        
        SAMLParms samlParms = new SAMLParms();
        samlParms.setCallbackHandler(callbackHandler);
        AssertionWrapper assertion = new AssertionWrapper(samlParms);

        WSSecSAMLToken wsSign = new WSSecSAMLToken();

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        Document unsignedDoc = wsSign.build(doc, assertion, secHeader);

        String outputString = 
            org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(unsignedDoc);
        if (LOG.isDebugEnabled()) {
            LOG.debug("SAML 2 Authn Assertion (sender vouches):");
            LOG.debug(outputString);
        }
        assertTrue(outputString.contains("12.34.56.78"));
        assertTrue(outputString.contains("test-dns"));
        
        List<WSSecurityEngineResult> results = verify(unsignedDoc);
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.ST_UNSIGNED);
        AssertionWrapper receivedAssertion = 
            (AssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedAssertion != null);
        assertTrue(!receivedAssertion.isSigned());
    }
    
    /**
     * Test that creates, sends and processes an unsigned SAML 1.1 authorization assertion
     * with a Resource URI.
     */
    @org.junit.Test
    public void testSAML1Resource() throws Exception {
        SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
        callbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHZ);
        callbackHandler.setIssuer("www.example.com");
        callbackHandler.setResource("http://resource.org");
        
        SAMLParms samlParms = new SAMLParms();
        samlParms.setCallbackHandler(callbackHandler);
        AssertionWrapper assertion = new AssertionWrapper(samlParms);

        WSSecSAMLToken wsSign = new WSSecSAMLToken();

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        Document unsignedDoc = wsSign.build(doc, assertion, secHeader);

        String outputString = 
            org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(unsignedDoc);
        if (LOG.isDebugEnabled()) {
            LOG.debug("SAML 1.1 Authz Assertion (sender vouches):");
            LOG.debug(outputString);
        }
        assertTrue(outputString.contains("http://resource.org"));
        
        List<WSSecurityEngineResult> results = verify(unsignedDoc);
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.ST_UNSIGNED);
        AssertionWrapper receivedAssertion = 
            (AssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedAssertion != null);
        assertTrue(!receivedAssertion.isSigned());
    }
    
    /**
     * Test that creates, sends and processes an unsigned SAML 2 attribute assertion. The attributeValue
     * has a custom XMLObject (not a String) value.
     */
    @org.junit.Test
    @SuppressWarnings("unchecked")
    public void testSAML2AttrAssertionCustomAttribute() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.ATTR);
        callbackHandler.setIssuer("www.example.com");
        
        // Create and add a custom Attribute (conditions Object)
        XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();
        
        SAMLObjectBuilder<Conditions> conditionsV2Builder = 
                (SAMLObjectBuilder<Conditions>)builderFactory.getBuilder(Conditions.DEFAULT_ELEMENT_NAME);
        Conditions conditions = conditionsV2Builder.buildObject();
        DateTime newNotBefore = new DateTime();
        conditions.setNotBefore(newNotBefore);
        conditions.setNotOnOrAfter(newNotBefore.plusMinutes(5));
        
        XMLObjectBuilder<XSAny> xsAnyBuilder = builderFactory.getBuilder(XSAny.TYPE_NAME);
        XSAny attributeValue = xsAnyBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME);
        attributeValue.getUnknownXMLObjects().add(conditions);
        
        callbackHandler.setCustomAttributeValues(Collections.singletonList(attributeValue));

        SAMLParms samlParms = new SAMLParms();
        samlParms.setCallbackHandler(callbackHandler);
        AssertionWrapper assertion = new AssertionWrapper(samlParms);

        WSSecSAMLToken wsSign = new WSSecSAMLToken();

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        Document unsignedDoc = wsSign.build(doc, assertion, secHeader);

        if (LOG.isDebugEnabled()) {
            LOG.debug("SAML 2 Attr Assertion (sender vouches):");
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(unsignedDoc);
            LOG.debug(outputString);
        }
        
        List<WSSecurityEngineResult> results = verify(unsignedDoc);
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.ST_UNSIGNED);
        AssertionWrapper receivedAssertion = 
            (AssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedAssertion != null);
        assertTrue(!receivedAssertion.isSigned());
    }
    
    /**
     * Test that creates, sends and processes an unsigned SAML 2 authentication assertion with
     * SubjectConfirmationData information.
     */
    @org.junit.Test
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
        
        SAMLParms samlParms = new SAMLParms();
        samlParms.setCallbackHandler(callbackHandler);
        AssertionWrapper assertion = new AssertionWrapper(samlParms);

        WSSecSAMLToken wsSign = new WSSecSAMLToken();

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        Document unsignedDoc = wsSign.build(doc, assertion, secHeader);

        String outputString = 
            org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(unsignedDoc);
        if (LOG.isDebugEnabled()) {
            LOG.debug("SAML 2 Authn Assertion (sender vouches):");
            LOG.debug(outputString);
        }
        assertTrue(outputString.contains("http://recipient.apache.org"));
        
        List<WSSecurityEngineResult> results = verify(unsignedDoc);
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.ST_UNSIGNED);
        AssertionWrapper receivedAssertion = 
            (AssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedAssertion != null);
        assertTrue(!receivedAssertion.isSigned());
    }
    
    /**
     * Test that creates, sends and processes an unsigned SAML 2 authentication assertion, which
     * is encrypted in a saml2:EncryptedAssertion Element in the security header
     */
    @org.junit.Test
    public void testSAML2EncryptedAssertion() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
        callbackHandler.setIssuer("www.example.com");
        
        SAMLParms samlParms = new SAMLParms();
        samlParms.setCallbackHandler(callbackHandler);
        AssertionWrapper assertion = new AssertionWrapper(samlParms);
        
        WSSecSAMLToken wsSign = new WSSecSAMLToken();

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        wsSign.prepare(doc, assertion);
        
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
                WSConstants.KEYTRANSPORT_RSAOEP, certs[0], false);
        
        if (LOG.isDebugEnabled()) {
            String outputString = 
                XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }
        
        List<WSSecurityEngineResult> results = 
            secEngine.processSecurityHeader(doc, null, new KeystoreCallbackHandler(), crypto);
        
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.ST_UNSIGNED);
        AssertionWrapper receivedSamlAssertion =
            (AssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedSamlAssertion != null);
        assertTrue(receivedSamlAssertion.getElement() != null);
        assertTrue("Assertion".equals(receivedSamlAssertion.getElement().getLocalName()));
        
        actionResult = WSSecurityUtil.fetchActionResult(results, WSConstants.ENCR);
        assertTrue(actionResult != null);
    }
    
    @org.junit.Test
    public void testRequiredSubjectConfirmationMethod() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
        callbackHandler.setIssuer("www.example.com");
        
        SAMLParms samlParms = new SAMLParms();
        samlParms.setCallbackHandler(callbackHandler);
        AssertionWrapper samlAssertion = new AssertionWrapper(samlParms);
        
        WSSecSAMLToken wsSign = new WSSecSAMLToken();

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        Document unsignedDoc = wsSign.build(doc, samlAssertion, secHeader);

        WSSConfig config = WSSConfig.getNewInstance();
        SamlAssertionValidator assertionValidator = new SamlAssertionValidator();
        assertionValidator.setRequiredSubjectConfirmationMethod(SAML2Constants.CONF_SENDER_VOUCHES);
        config.setValidator(WSSecurityEngine.SAML_TOKEN, assertionValidator);
        config.setValidator(WSSecurityEngine.SAML2_TOKEN, assertionValidator);
        
        WSSecurityEngine newEngine = new WSSecurityEngine();
        newEngine.setWssConfig(config);
        newEngine.processSecurityHeader(unsignedDoc, null, null, null);
        
        // Now create a Bearer assertion
        callbackHandler.setConfirmationMethod(SAML2Constants.CONF_BEARER);
        
        samlParms = new SAMLParms();
        samlParms.setCallbackHandler(callbackHandler);
        samlAssertion = new AssertionWrapper(samlParms);

        wsSign = new WSSecSAMLToken();

        doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        unsignedDoc = wsSign.build(doc, samlAssertion, secHeader);
        try {
            newEngine.processSecurityHeader(unsignedDoc, null, null, null);
            fail("Failure expected on an incorrect subject confirmation method");
        } catch (WSSecurityException ex) {
            // expected
        }
    }
    
    @org.junit.Test
    public void testStandardSubjectConfirmationMethod() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
        callbackHandler.setIssuer("www.example.com");
        callbackHandler.setConfirmationMethod("urn:oasis:names:tc:SAML:2.0:cm:custom");
        
        SAMLParms samlParms = new SAMLParms();
        samlParms.setCallbackHandler(callbackHandler);
        AssertionWrapper samlAssertion = new AssertionWrapper(samlParms);

        WSSecSAMLToken wsSign = new WSSecSAMLToken();

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        Document unsignedDoc = wsSign.build(doc, samlAssertion, secHeader);
        
        WSSecurityEngine newEngine = new WSSecurityEngine();
        try {
            newEngine.processSecurityHeader(unsignedDoc, null, null, null);
            fail("Failure expected on an unknown subject confirmation method");
        } catch (WSSecurityException ex) {
            // expected
        }

        // Now disable this check
        WSSConfig config = WSSConfig.getNewInstance();
        SamlAssertionValidator assertionValidator = new SamlAssertionValidator();
        assertionValidator.setRequireStandardSubjectConfirmationMethod(false);
        config.setValidator(WSSecurityEngine.SAML_TOKEN, assertionValidator);
        config.setValidator(WSSecurityEngine.SAML2_TOKEN, assertionValidator);
        
        newEngine.setWssConfig(config);
        newEngine.processSecurityHeader(unsignedDoc, null, null, null);
    }
    
    @org.junit.Test
    public void testUnsignedBearer() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
        callbackHandler.setIssuer("www.example.com");
        callbackHandler.setConfirmationMethod(SAML2Constants.CONF_BEARER);
        
        SAMLParms samlParms = new SAMLParms();
        samlParms.setCallbackHandler(callbackHandler);
        AssertionWrapper samlAssertion = new AssertionWrapper(samlParms);

        WSSecSAMLToken wsSign = new WSSecSAMLToken();

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        Document unsignedDoc = wsSign.build(doc, samlAssertion, secHeader);
        
        WSSecurityEngine newEngine = new WSSecurityEngine();
        try {
            newEngine.processSecurityHeader(unsignedDoc, null, null, null);
            fail("Failure expected on an unsigned bearer token");
        } catch (WSSecurityException ex) {
            // expected
        }

        // Now disable this check
        WSSConfig config = WSSConfig.getNewInstance();
        SamlAssertionValidator assertionValidator = new SamlAssertionValidator();
        assertionValidator.setRequireBearerSignature(false);
        config.setValidator(WSSecurityEngine.SAML_TOKEN, assertionValidator);
        config.setValidator(WSSecurityEngine.SAML2_TOKEN, assertionValidator);
        
        newEngine.setWssConfig(config);
        newEngine.processSecurityHeader(unsignedDoc, null, null, null);
    }
    
    private void encryptElement(
        Document document,
        Element elementToEncrypt,
        String algorithm,
        Key encryptingKey,
        String keyTransportAlgorithm,
        X509Certificate wrappingCert,
        boolean content
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
            
            SecurityTokenReference securityTokenReference = new SecurityTokenReference(document);
            securityTokenReference.addWSSENamespace();
            securityTokenReference.setKeyIdentifierSKI(wrappingCert, null);
            encryptedKeyKeyInfo.addUnknownElement(securityTokenReference.getElement());

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

    /**
     * Verifies the soap envelope
     * <p/>
     * 
     * @param envelope 
     * @throws Exception Thrown when there is a problem in verification
     */
    private List<WSSecurityEngineResult> verify(Document doc) throws Exception {
        List<WSSecurityEngineResult> results = 
                secEngine.processSecurityHeader(doc, null, null, null);
        String outputString = 
            org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
        assertTrue(outputString.indexOf("counter_port_type") > 0 ? true : false);
        return results;
    }

}
