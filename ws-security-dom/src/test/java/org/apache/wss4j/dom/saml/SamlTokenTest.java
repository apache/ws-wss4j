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

import org.apache.wss4j.common.saml.SamlAssertionWrapper;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.WSSConfig;
import org.apache.wss4j.dom.WSSecurityEngine;
import org.apache.wss4j.dom.WSSecurityEngineResult;
import org.apache.wss4j.dom.common.CustomHandler;
import org.apache.wss4j.dom.common.CustomSamlAssertionValidator;
import org.apache.wss4j.dom.common.SAML1CallbackHandler;
import org.apache.wss4j.dom.common.SAML2CallbackHandler;
import org.apache.wss4j.dom.common.SAMLElementCallbackHandler;
import org.apache.wss4j.dom.common.SOAPUtil;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.saml.SAMLCallback;
import org.apache.wss4j.common.saml.SAMLUtil;
import org.apache.wss4j.common.saml.bean.SubjectConfirmationDataBean;
import org.apache.wss4j.common.saml.builder.SAML1Constants;
import org.apache.wss4j.common.util.XMLUtils;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.handler.WSHandlerConstants;
import org.apache.wss4j.dom.message.WSSecHeader;
import org.apache.wss4j.dom.message.WSSecSAMLToken;
import org.apache.wss4j.dom.util.WSSecurityUtil;

import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.saml2.core.AttributeValue;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.xml.XMLObjectBuilder;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.schema.XSAny;
import org.w3c.dom.Document;

import java.util.Collections;
import java.util.List;

/**
 * Test-case for sending and processing an unsigned (sender vouches) SAML Assertion.
 */
public class SamlTokenTest extends org.junit.Assert {
    private static final org.slf4j.Logger LOG = 
        org.slf4j.LoggerFactory.getLogger(SamlTokenTest.class);
    private WSSecurityEngine secEngine = new WSSecurityEngine();

    public SamlTokenTest() {
        WSSConfig config = WSSConfig.getNewInstance();
        config.setValidator(WSSecurityEngine.SAML_TOKEN, new CustomSamlAssertionValidator());
        config.setValidator(WSSecurityEngine.SAML2_TOKEN, new CustomSamlAssertionValidator());
        config.setValidateSamlSubjectConfirmation(false);
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
        
        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper samlAssertion = new SamlAssertionWrapper(samlCallback);

        WSSecSAMLToken wsSign = new WSSecSAMLToken();

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        Document unsignedDoc = wsSign.build(doc, samlAssertion, secHeader);

        if (LOG.isDebugEnabled()) {
            LOG.debug("SAML 1.1 Authn Assertion (sender vouches):");
            String outputString = 
                XMLUtils.PrettyDocumentToString(unsignedDoc);
            LOG.debug(outputString);
        }
        
        List<WSSecurityEngineResult> results = verify(unsignedDoc);
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.ST_UNSIGNED);
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
    @org.junit.Test
    public void testSAML1AuthnAssertionViaElement() throws Exception {
        SAMLElementCallbackHandler callbackHandler = new SAMLElementCallbackHandler();
        callbackHandler.setIssuer("www.example.com");
        
        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper samlAssertion = new SamlAssertionWrapper(samlCallback);
        
        WSSecSAMLToken wsSign = new WSSecSAMLToken();

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        Document unsignedDoc = wsSign.build(doc, samlAssertion, secHeader);

        if (LOG.isDebugEnabled()) {
            LOG.debug("SAML 1.1 Authn Assertion (sender vouches - from an Element):");
            String outputString = 
                XMLUtils.PrettyDocumentToString(unsignedDoc);
            LOG.debug(outputString);
        }
        
        List<WSSecurityEngineResult> results = verify(unsignedDoc);
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.ST_UNSIGNED);
        SamlAssertionWrapper receivedSamlAssertion =
            (SamlAssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedSamlAssertion != null);
        assertFalse(receivedSamlAssertion.isSigned());
        assertTrue(receivedSamlAssertion.getSignatureValue() == null);
    }
    
    /**
     * Test that creates, sends and processes an unsigned SAML 1.1 attribute assertion.
     */
    @org.junit.Test
    public void testSAML1AttrAssertion() throws Exception {
        SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
        callbackHandler.setStatement(SAML1CallbackHandler.Statement.ATTR);
        callbackHandler.setIssuer("www.example.com");
        
        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper samlAssertion = new SamlAssertionWrapper(samlCallback);

        WSSecSAMLToken wsSign = new WSSecSAMLToken();

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        Document unsignedDoc = wsSign.build(doc, samlAssertion, secHeader);

        if (LOG.isDebugEnabled()) {
            LOG.debug("SAML 1.1 Attr Assertion (sender vouches):");
            String outputString = 
                XMLUtils.PrettyDocumentToString(unsignedDoc);
            LOG.debug(outputString);
        }
        
        List<WSSecurityEngineResult> results = verify(unsignedDoc);
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.ST_UNSIGNED);
        SamlAssertionWrapper receivedSamlAssertion =
            (SamlAssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedSamlAssertion != null);
        assertFalse(receivedSamlAssertion.isSigned());
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
        
        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper samlAssertion = new SamlAssertionWrapper(samlCallback);

        WSSecSAMLToken wsSign = new WSSecSAMLToken();

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        Document unsignedDoc = wsSign.build(doc, samlAssertion, secHeader);

        if (LOG.isDebugEnabled()) {
            LOG.debug("SAML 1.1 Authz Assertion (sender vouches):");
            String outputString = 
                XMLUtils.PrettyDocumentToString(unsignedDoc);
            LOG.debug(outputString);
        }
        
        List<WSSecurityEngineResult> results = verify(unsignedDoc);
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.ST_UNSIGNED);
        SamlAssertionWrapper receivedSamlAssertion =
            (SamlAssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedSamlAssertion != null);
        assertFalse(receivedSamlAssertion.isSigned());
    }
    
    /**
     * Test that creates, sends and processes an unsigned SAML 2 authentication assertion.
     */
    @org.junit.Test
    public void testSAML2AuthnAssertion() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
        callbackHandler.setIssuer("www.example.com");
        
        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper samlAssertion = new SamlAssertionWrapper(samlCallback);

        WSSecSAMLToken wsSign = new WSSecSAMLToken();

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        Document unsignedDoc = wsSign.build(doc, samlAssertion, secHeader);

        if (LOG.isDebugEnabled()) {
            LOG.debug("SAML 2 Authn Assertion (sender vouches):");
            String outputString = 
                XMLUtils.PrettyDocumentToString(unsignedDoc);
            LOG.debug(outputString);
        }
        
        List<WSSecurityEngineResult> results = verify(unsignedDoc);
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.ST_UNSIGNED);
        SamlAssertionWrapper receivedSamlAssertion =
            (SamlAssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedSamlAssertion != null);
        assertFalse(receivedSamlAssertion.isSigned());
    }
    
    /**
     * Test that creates, sends and processes an unsigned SAML 2 attribute assertion.
     */
    @org.junit.Test
    public void testSAML2AttrAssertion() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.ATTR);
        callbackHandler.setIssuer("www.example.com");
        
        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper samlAssertion = new SamlAssertionWrapper(samlCallback);
        WSSecSAMLToken wsSign = new WSSecSAMLToken();

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        Document unsignedDoc = wsSign.build(doc, samlAssertion, secHeader);

        if (LOG.isDebugEnabled()) {
            LOG.debug("SAML 2 Attr Assertion (sender vouches):");
            String outputString = 
                XMLUtils.PrettyDocumentToString(unsignedDoc);
            LOG.debug(outputString);
        }
        
        List<WSSecurityEngineResult> results = verify(unsignedDoc);
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.ST_UNSIGNED);
        SamlAssertionWrapper receivedSamlAssertion =
            (SamlAssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedSamlAssertion != null);
        assertFalse(receivedSamlAssertion.isSigned());
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
        
        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper samlAssertion = new SamlAssertionWrapper(samlCallback);

        WSSecSAMLToken wsSign = new WSSecSAMLToken();

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        Document unsignedDoc = wsSign.build(doc, samlAssertion, secHeader);

        if (LOG.isDebugEnabled()) {
            LOG.debug("SAML 2 Authz Assertion (sender vouches):");
            String outputString = 
                XMLUtils.PrettyDocumentToString(unsignedDoc);
            LOG.debug(outputString);
        }
        
        List<WSSecurityEngineResult> results = verify(unsignedDoc);
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.ST_UNSIGNED);
        SamlAssertionWrapper receivedSamlAssertion =
            (SamlAssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedSamlAssertion != null);
        assertFalse(receivedSamlAssertion.isSigned());
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
        config.put(WSHandlerConstants.SAML_CALLBACK_REF, new SAML1CallbackHandler());
        reqData.setMsgContext(config);
        
        final java.util.List<Integer> actions = new java.util.ArrayList<Integer>();
        actions.add(action);
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
            XMLUtils.PrettyDocumentToString(doc);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Unsigned SAML 1.1 authentication assertion via an Action:");
            LOG.debug(outputString);
        }
        assertFalse (outputString.contains("Signature"));
        
        List<WSSecurityEngineResult> results = verify(doc);
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.ST_UNSIGNED);
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
    @org.junit.Test
    public void testSAML1AuthnBadIssuerAssertion() throws Exception {
        SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
        callbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHN);
        callbackHandler.setIssuer("www.example2.com");
        
        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper samlAssertion = new SamlAssertionWrapper(samlCallback);

        WSSecSAMLToken wsSign = new WSSecSAMLToken();

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        Document unsignedDoc = wsSign.build(doc, samlAssertion, secHeader);

        if (LOG.isDebugEnabled()) {
            LOG.debug("SAML 1.1 Authn Assertion (sender vouches):");
            String outputString = 
                XMLUtils.PrettyDocumentToString(unsignedDoc);
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
        
        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper samlAssertion = new SamlAssertionWrapper(samlCallback);

        WSSecSAMLToken wsSign = new WSSecSAMLToken();

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        Document unsignedDoc = wsSign.build(doc, samlAssertion, secHeader);

        if (LOG.isDebugEnabled()) {
            LOG.debug("SAML 2 Authn Assertion (sender vouches):");
            String outputString = 
                XMLUtils.PrettyDocumentToString(unsignedDoc);
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
        
        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper samlAssertion = new SamlAssertionWrapper(samlCallback);

        WSSecSAMLToken wsSign = new WSSecSAMLToken();

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        Document unsignedDoc = wsSign.build(doc, samlAssertion, secHeader);

        String outputString = 
            XMLUtils.PrettyDocumentToString(unsignedDoc);
        if (LOG.isDebugEnabled()) {
            LOG.debug("SAML 1.1 Authn Assertion (sender vouches):");
            LOG.debug(outputString);
        }
        assertTrue(outputString.contains(SAML1Constants.NAMEID_FORMAT_EMAIL_ADDRESS));
        
        List<WSSecurityEngineResult> results = verify(unsignedDoc);
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.ST_UNSIGNED);
        SamlAssertionWrapper receivedSamlAssertion =
            (SamlAssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedSamlAssertion != null);
        assertFalse(receivedSamlAssertion.isSigned());
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
        
        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper samlAssertion = new SamlAssertionWrapper(samlCallback);

        WSSecSAMLToken wsSign = new WSSecSAMLToken();

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        Document unsignedDoc = wsSign.build(doc, samlAssertion, secHeader);

        String outputString = 
            XMLUtils.PrettyDocumentToString(unsignedDoc);
        if (LOG.isDebugEnabled()) {
            LOG.debug("SAML 2 Authn Assertion (sender vouches):");
            LOG.debug(outputString);
        }
        assertTrue(outputString.contains(SAML1Constants.NAMEID_FORMAT_EMAIL_ADDRESS));
        
        List<WSSecurityEngineResult> results = verify(unsignedDoc);
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.ST_UNSIGNED);
        SamlAssertionWrapper receivedSamlAssertion =
            (SamlAssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedSamlAssertion != null);
        assertFalse(receivedSamlAssertion.isSigned());
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
        callbackHandler.setSubjectLocality("12.34.56.780", "test-dns");
        
        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper samlAssertion = new SamlAssertionWrapper(samlCallback);

        WSSecSAMLToken wsSign = new WSSecSAMLToken();

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        Document unsignedDoc = wsSign.build(doc, samlAssertion, secHeader);

        String outputString = 
            XMLUtils.PrettyDocumentToString(unsignedDoc);
        if (LOG.isDebugEnabled()) {
            LOG.debug("SAML 1.1 Authn Assertion (sender vouches):");
            LOG.debug(outputString);
        }
        assertTrue(outputString.contains("12.34.56.780"));
        assertTrue(outputString.contains("test-dns"));
        
        List<WSSecurityEngineResult> results = verify(unsignedDoc);
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.ST_UNSIGNED);
        SamlAssertionWrapper receivedSamlAssertion =
            (SamlAssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
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
        callbackHandler.setSubjectLocality("12.34.56.780", "test-dns");
        
        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper samlAssertion = new SamlAssertionWrapper(samlCallback);

        WSSecSAMLToken wsSign = new WSSecSAMLToken();

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        Document unsignedDoc = wsSign.build(doc, samlAssertion, secHeader);

        String outputString = 
            XMLUtils.PrettyDocumentToString(unsignedDoc);
        if (LOG.isDebugEnabled()) {
            LOG.debug("SAML 2 Authn Assertion (sender vouches):");
            LOG.debug(outputString);
        }
        assertTrue(outputString.contains("12.34.56.780"));
        assertTrue(outputString.contains("test-dns"));
        
        List<WSSecurityEngineResult> results = verify(unsignedDoc);
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.ST_UNSIGNED);
        SamlAssertionWrapper receivedSamlAssertion =
            (SamlAssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedSamlAssertion != null);
        assertFalse(receivedSamlAssertion.isSigned());
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
        
        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper samlAssertion = new SamlAssertionWrapper(samlCallback);

        WSSecSAMLToken wsSign = new WSSecSAMLToken();

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        Document unsignedDoc = wsSign.build(doc, samlAssertion, secHeader);

        String outputString = 
            XMLUtils.PrettyDocumentToString(unsignedDoc);
        if (LOG.isDebugEnabled()) {
            LOG.debug("SAML 1.1 Authz Assertion (sender vouches):");
            LOG.debug(outputString);
        }
        assertTrue(outputString.contains("http://resource.org"));
        
        List<WSSecurityEngineResult> results = verify(unsignedDoc);
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.ST_UNSIGNED);
        SamlAssertionWrapper receivedSamlAssertion =
            (SamlAssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedSamlAssertion != null);
        assertFalse(receivedSamlAssertion.isSigned());
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

        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper samlAssertion = new SamlAssertionWrapper(samlCallback);

        WSSecSAMLToken wsSign = new WSSecSAMLToken();

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        Document unsignedDoc = wsSign.build(doc, samlAssertion, secHeader);

        if (LOG.isDebugEnabled()) {
            LOG.debug("SAML 2 Attr Assertion (sender vouches):");
            String outputString = 
                XMLUtils.PrettyDocumentToString(unsignedDoc);
            LOG.debug(outputString);
        }
        
        List<WSSecurityEngineResult> results = verify(unsignedDoc);
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.ST_UNSIGNED);
        SamlAssertionWrapper receivedSamlAssertion =
            (SamlAssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedSamlAssertion != null);
        assertFalse(receivedSamlAssertion.isSigned());
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
        
        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper samlAssertion = new SamlAssertionWrapper(samlCallback);
        
        WSSecSAMLToken wsSign = new WSSecSAMLToken();

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        Document unsignedDoc = wsSign.build(doc, samlAssertion, secHeader);

        String outputString = 
            XMLUtils.PrettyDocumentToString(unsignedDoc);
        if (LOG.isDebugEnabled()) {
            LOG.debug("SAML 2 Authn Assertion (sender vouches):");
            LOG.debug(outputString);
        }
        assertTrue(outputString.contains("http://recipient.apache.org"));
        
        List<WSSecurityEngineResult> results = verify(unsignedDoc);
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.ST_UNSIGNED);
        SamlAssertionWrapper receivedSamlAssertion =
            (SamlAssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedSamlAssertion != null);
        assertFalse(receivedSamlAssertion.isSigned());
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
            XMLUtils.PrettyDocumentToString(doc);
        assertTrue(outputString.indexOf("counter_port_type") > 0 ? true : false);
        return results;
    }
    
}
