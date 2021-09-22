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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.security.auth.callback.CallbackHandler;

import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.saml.SAMLCallback;
import org.apache.wss4j.common.saml.SAMLUtil;
import org.apache.wss4j.common.saml.SamlAssertionWrapper;
import org.apache.wss4j.common.saml.bean.AudienceRestrictionBean;
import org.apache.wss4j.common.saml.bean.ConditionsBean;
import org.apache.wss4j.common.saml.bean.DelegateBean;
import org.apache.wss4j.common.saml.bean.NameIDBean;
import org.apache.wss4j.common.saml.bean.ProxyRestrictionBean;
import org.apache.wss4j.common.saml.builder.SAML2Constants;
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
 * Test-case for sending and processing an a SAML Token with a custom Conditions element.
 */
public class SamlConditionsTest {
    private static final org.slf4j.Logger LOG =
        org.slf4j.LoggerFactory.getLogger(SamlConditionsTest.class);
    private WSSecurityEngine secEngine = new WSSecurityEngine();

    public SamlConditionsTest() {
        WSSConfig config = WSSConfig.getNewInstance();
        config.setValidator(WSConstants.SAML_TOKEN, new CustomSamlAssertionValidator());
        config.setValidator(WSConstants.SAML2_TOKEN, new CustomSamlAssertionValidator());
        secEngine.setWssConfig(config);
    }

    /**
     * Test that creates, sends and processes an unsigned SAML 1.1 authentication assertion
     * with a custom Conditions statement.
     */
    @Test
    public void testSAML1Conditions() throws Exception {
        SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
        callbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHN);
        callbackHandler.setIssuer("www.example.com");

        ConditionsBean conditions = new ConditionsBean();
        DateTime notBefore = new DateTime();
        conditions.setNotBefore(notBefore);
        conditions.setNotAfter(notBefore.plusMinutes(20));
        callbackHandler.setConditions(conditions);

        createAndVerifyMessage(callbackHandler, true);
    }

    /**
     * Test that creates, sends and processes an unsigned SAML 2 authentication assertion
     * with an (invalid) custom Conditions statement.
     */
    @Test
    public void testSAML2InvalidAfterConditions() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
        callbackHandler.setIssuer("www.example.com");

        ConditionsBean conditions = new ConditionsBean();
        DateTime notBefore = new DateTime();
        conditions.setNotBefore(notBefore.minusMinutes(5));
        conditions.setNotAfter(notBefore.minusMinutes(3));
        callbackHandler.setConditions(conditions);

        createAndVerifyMessage(callbackHandler, false);
    }

    @Test
    public void testSAML2StaleNotOnOrAfter() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
        callbackHandler.setIssuer("www.example.com");

        ConditionsBean conditions = new ConditionsBean();
        DateTime notBefore = new DateTime();
        conditions.setNotAfter(notBefore.minusMinutes(60));
        conditions.setNotBefore(notBefore.minusMinutes(70));
        callbackHandler.setConditions(conditions);

        createAndVerifyMessage(callbackHandler, false);
    }

    @Test
    public void testSAML2FutureNotBefore() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
        callbackHandler.setIssuer("www.example.com");

        ConditionsBean conditions = new ConditionsBean();
        DateTime notBefore = new DateTime();
        conditions.setNotAfter(new DateTime().plusMinutes(70));
        conditions.setNotBefore(notBefore.plusMinutes(60));
        callbackHandler.setConditions(conditions);

        createAndVerifyMessage(callbackHandler, false);
    }

    @Test
    public void testSAML2FutureIssueInstant() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
        callbackHandler.setIssuer("www.example.com");

        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper samlAssertion = new SamlAssertionWrapper(samlCallback);

        DateTime issueInstant = new DateTime();
        issueInstant = issueInstant.plusMinutes(60);
        samlAssertion.getSaml2().setIssueInstant(issueInstant);

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecSAMLToken wsSign = new WSSecSAMLToken(secHeader);

        Document unsignedDoc = wsSign.build(samlAssertion);

        if (LOG.isDebugEnabled()) {
            LOG.debug("SAML 2 Authn Assertion (sender vouches):");
            String outputString =
                XMLUtils.prettyDocumentToString(unsignedDoc);
            LOG.debug(outputString);
        }

        try {
            verify(unsignedDoc);
            fail("Failure expected in processing the SAML Conditions element");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getMessage().contains("SAML token security failure"));
        }
    }

    @Test
    public void testSAML2StaleIssueInstant() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
        callbackHandler.setIssuer("www.example.com");

        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper samlAssertion = new SamlAssertionWrapper(samlCallback);

        DateTime issueInstant = new DateTime();
        issueInstant = issueInstant.minusMinutes(31);
        samlAssertion.getSaml2().setIssueInstant(issueInstant);
        samlAssertion.getSaml2().getConditions().setNotOnOrAfter(null);

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecSAMLToken wsSign = new WSSecSAMLToken(secHeader);

        Document unsignedDoc = wsSign.build(samlAssertion);

        if (LOG.isDebugEnabled()) {
            LOG.debug("SAML 2 Authn Assertion (sender vouches):");
            String outputString =
                XMLUtils.prettyDocumentToString(unsignedDoc);
            LOG.debug(outputString);
        }

        try {
            verify(unsignedDoc);
            fail("Failure expected in processing a stale SAML Assertion");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getMessage().contains("SAML token security failure"));
        }
    }

    @Test
    public void testSAML2NoNotOnOrAfter() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
        callbackHandler.setIssuer("www.example.com");

        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper samlAssertion = new SamlAssertionWrapper(samlCallback);

        DateTime issueInstant = new DateTime().minusSeconds(5);
        samlAssertion.getSaml2().setIssueInstant(issueInstant);
        samlAssertion.getSaml2().getConditions().setNotOnOrAfter(null);

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecSAMLToken wsSign = new WSSecSAMLToken(secHeader);

        Document unsignedDoc = wsSign.build(samlAssertion);

        if (LOG.isDebugEnabled()) {
            LOG.debug("SAML 2 Authn Assertion (sender vouches):");
            String outputString =
                XMLUtils.prettyDocumentToString(unsignedDoc);
            LOG.debug(outputString);
        }

        verify(unsignedDoc);
    }

    @Test
    public void testSAML2StaleIssueInstantButWithNotOnOrAfter() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
        callbackHandler.setIssuer("www.example.com");

        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper samlAssertion = new SamlAssertionWrapper(samlCallback);

        ConditionsBean conditions = new ConditionsBean();
        conditions.setNotBefore(new DateTime());
        conditions.setNotAfter(new DateTime().plusMinutes(35));

        DateTime issueInstant = new DateTime();
        issueInstant = issueInstant.minusMinutes(31);
        samlAssertion.getSaml2().setIssueInstant(issueInstant);

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecSAMLToken wsSign = new WSSecSAMLToken(secHeader);

        Document unsignedDoc = wsSign.build(samlAssertion);

        if (LOG.isDebugEnabled()) {
            LOG.debug("SAML 2 Authn Assertion (sender vouches):");
            String outputString =
                XMLUtils.prettyDocumentToString(unsignedDoc);
            LOG.debug(outputString);
        }

        verify(unsignedDoc);
    }

    @Test
    public void testSAML1StaleIssueInstant() throws Exception {
        SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
        callbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHN);
        callbackHandler.setIssuer("www.example.com");

        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper samlAssertion = new SamlAssertionWrapper(samlCallback);

        DateTime issueInstant = new DateTime();
        issueInstant = issueInstant.minusMinutes(31);
        samlAssertion.getSaml1().setIssueInstant(issueInstant);
        samlAssertion.getSaml1().getConditions().setNotOnOrAfter(null);

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecSAMLToken wsSign = new WSSecSAMLToken(secHeader);

        Document unsignedDoc = wsSign.build(samlAssertion);

        if (LOG.isDebugEnabled()) {
            LOG.debug("SAML 1 Authn Assertion (sender vouches):");
            String outputString =
                XMLUtils.prettyDocumentToString(unsignedDoc);
            LOG.debug(outputString);
        }

        try {
            verify(unsignedDoc);
            fail("Failure expected in processing a stale SAML Assertion");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getMessage().contains("SAML token security failure"));
        }
    }

    /**
     * Test that creates, sends and processes an unsigned SAML 2 authentication assertion
     * with an (invalid) custom Conditions statement.
     */
    @Test
    public void testSAML2InvalidBeforeConditions() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
        callbackHandler.setIssuer("www.example.com");

        ConditionsBean conditions = new ConditionsBean();
        DateTime notBefore = new DateTime();
        conditions.setNotBefore(notBefore.plusMinutes(2));
        conditions.setNotAfter(notBefore.plusMinutes(5));
        callbackHandler.setConditions(conditions);

        createAndVerifyMessage(callbackHandler, false);
    }

    /**
     * Test that creates, sends and processes an unsigned SAML 2 authentication assertion
     * with a Conditions statement that has a NotBefore "in the future".
     */
    @Test
    public void testSAML2FutureTTLConditions() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
        callbackHandler.setIssuer("www.example.com");

        ConditionsBean conditions = new ConditionsBean();
        DateTime notBefore = new DateTime();
        conditions.setNotBefore(notBefore.plusSeconds(30));
        conditions.setNotAfter(notBefore.plusMinutes(5));
        callbackHandler.setConditions(conditions);

        createAndVerifyMessage(callbackHandler, true);
    }

    /**
     * Test that creates, sends and processes an unsigned SAML 2 authentication assertion
     * with a OneTimeUse Element
     */
    @Test
    public void testSAML2OneTimeUse() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
        callbackHandler.setIssuer("www.example.com");

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

        verify(unsignedDoc);
    }

    /**
     * Test that creates, sends and processes an unsigned SAML 2 authentication assertion
     * with a ProxyRestriction Element
     */
    @Test
    public void testSAML2ProxyRestriction() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
        callbackHandler.setIssuer("www.example.com");

        ConditionsBean conditions = new ConditionsBean();
        conditions.setTokenPeriodMinutes(5);
        ProxyRestrictionBean proxyRestriction = new ProxyRestrictionBean();
        List<String> audiences = new ArrayList<>();
        audiences.add("http://apache.org/one");
        audiences.add("http://apache.org/two");
        proxyRestriction.getAudienceURIs().addAll(audiences);
        proxyRestriction.setCount(5);
        conditions.setProxyRestriction(proxyRestriction);

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
        assertTrue(outputString.contains("ProxyRestriction"));
        if (LOG.isDebugEnabled()) {
            LOG.debug(outputString);
        }

        verify(unsignedDoc);
    }

    /**
     * Test that creates, sends and processes an unsigned SAML 2 authentication assertion
     * with an AudienceRestriction Element
     */
    @Test
    public void testSAML2AudienceRestriction() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
        callbackHandler.setIssuer("www.example.com");

        ConditionsBean conditions = new ConditionsBean();
        conditions.setTokenPeriodMinutes(5);
        List<String> audiences = new ArrayList<>();
        audiences.add("http://apache.org/one");
        audiences.add("http://apache.org/two");
        AudienceRestrictionBean audienceRestrictionBean = new AudienceRestrictionBean();
        audienceRestrictionBean.setAudienceURIs(audiences);
        conditions.setAudienceRestrictions(Collections.singletonList(audienceRestrictionBean));

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
        assertTrue(outputString.contains("AudienceRestriction"));
        if (LOG.isDebugEnabled()) {
            LOG.debug(outputString);
        }

        verify(unsignedDoc);
    }

    // Now test AudienceRestrictions with supplied restrictions
    @Test
    public void testSAML2AudienceRestrictionVerification() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
        callbackHandler.setIssuer("www.example.com");

        ConditionsBean conditions = new ConditionsBean();
        conditions.setTokenPeriodMinutes(5);
        List<String> audiences = new ArrayList<>();
        audiences.add("http://apache.org/one");
        audiences.add("http://apache.org/two");
        AudienceRestrictionBean audienceRestrictionBean = new AudienceRestrictionBean();
        audienceRestrictionBean.setAudienceURIs(audiences);
        conditions.setAudienceRestrictions(Collections.singletonList(audienceRestrictionBean));

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
        assertTrue(outputString.contains("AudienceRestriction"));
        if (LOG.isDebugEnabled()) {
            LOG.debug(outputString);
        }

        // This should fail as the expected audience isn't in the assertion
        audiences.clear();
        audiences.add("http://apache.org/three");

        WSSecurityEngine newEngine = new WSSecurityEngine();
        RequestData data = new RequestData();
        data.setAudienceRestrictions(audiences);
        data.setValidateSamlSubjectConfirmation(false);

        try {
            newEngine.processSecurityHeader(doc, data);
            fail("Failure expected on a bad audience restriction");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getMessage().contains("SAML token security failure"));
        }

        // Now add the correct audience back in...
        audiences.add("http://apache.org/one");
        data.setAudienceRestrictions(audiences);

        newEngine.processSecurityHeader(doc, data);
    }

    // Now test AudienceRestrictions with supplied restrictions
    @Test
    public void testSAML1AudienceRestrictionVerification() throws Exception {
        SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
        callbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHN);
        callbackHandler.setIssuer("www.example.com");

        ConditionsBean conditions = new ConditionsBean();
        conditions.setTokenPeriodMinutes(5);
        List<String> audiences = new ArrayList<>();
        audiences.add("http://apache.org/one");
        audiences.add("http://apache.org/two");
        AudienceRestrictionBean audienceRestrictionBean = new AudienceRestrictionBean();
        audienceRestrictionBean.setAudienceURIs(audiences);
        conditions.setAudienceRestrictions(Collections.singletonList(audienceRestrictionBean));

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
        assertTrue(outputString.contains("AudienceRestriction"));
        if (LOG.isDebugEnabled()) {
            LOG.debug(outputString);
        }

        // This should fail as the expected audience isn't in the assertion
        audiences.clear();
        audiences.add("http://apache.org/three");

        WSSecurityEngine newEngine = new WSSecurityEngine();
        RequestData data = new RequestData();
        data.setAudienceRestrictions(audiences);
        data.setValidateSamlSubjectConfirmation(false);

        try {
            newEngine.processSecurityHeader(doc, data);
            fail("Failure expected on a bad audience restriction");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getMessage().contains("SAML token security failure"));
        }

        // Now add the correct audience back in...
        audiences.add("http://apache.org/one");
        data.setAudienceRestrictions(audiences);

        newEngine.processSecurityHeader(doc, data);
    }

    /**
     * Test that creates, sends and processes an unsigned SAML 2 authentication assertion
     * with two AudienceRestriction Elements
     */
    @Test
    public void testSAML2AudienceRestrictionSeparateRestrictions() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
        callbackHandler.setIssuer("www.example.com");

        ConditionsBean conditions = new ConditionsBean();
        conditions.setTokenPeriodMinutes(5);

        List<AudienceRestrictionBean> audiencesRestrictions = new ArrayList<>();
        AudienceRestrictionBean audienceRestrictionBean = new AudienceRestrictionBean();
        audienceRestrictionBean.setAudienceURIs(Collections.singletonList("http://apache.org/one"));
        audiencesRestrictions.add(audienceRestrictionBean);

        audienceRestrictionBean = new AudienceRestrictionBean();
        audienceRestrictionBean.setAudienceURIs(Collections.singletonList("http://apache.org/two"));
        audiencesRestrictions.add(audienceRestrictionBean);

        conditions.setAudienceRestrictions(audiencesRestrictions);

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
        assertTrue(outputString.contains("AudienceRestriction"));
        if (LOG.isDebugEnabled()) {
            LOG.debug(outputString);
        }

        verify(unsignedDoc);
    }

    // Now test AudienceRestrictions with supplied restrictions
    @Test
    public void testSAML2AudienceRestrictionSeparateRestrictionsValidation() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
        callbackHandler.setIssuer("www.example.com");

        ConditionsBean conditions = new ConditionsBean();
        conditions.setTokenPeriodMinutes(5);

        List<AudienceRestrictionBean> audiencesRestrictions = new ArrayList<>();
        AudienceRestrictionBean audienceRestrictionBean = new AudienceRestrictionBean();
        audienceRestrictionBean.setAudienceURIs(Collections.singletonList("http://apache.org/one"));
        audiencesRestrictions.add(audienceRestrictionBean);

        audienceRestrictionBean = new AudienceRestrictionBean();
        audienceRestrictionBean.setAudienceURIs(Collections.singletonList("http://apache.org/two"));
        audiencesRestrictions.add(audienceRestrictionBean);

        conditions.setAudienceRestrictions(audiencesRestrictions);

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
        assertTrue(outputString.contains("AudienceRestriction"));
        if (LOG.isDebugEnabled()) {
            LOG.debug(outputString);
        }

        // This should fail as the expected audience isn't in the assertion
        List<String> audiences = new ArrayList<>();
        audiences.add("http://apache.org/three");

        WSSecurityEngine newEngine = new WSSecurityEngine();
        RequestData data = new RequestData();
        data.setAudienceRestrictions(audiences);
        data.setValidateSamlSubjectConfirmation(false);

        try {
            newEngine.processSecurityHeader(doc, data);
            fail("Failure expected on a bad audience restriction");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getMessage().contains("SAML token security failure"));
        }

        // Now add the correct audience back in...
        audiences.add("http://apache.org/one");
        data.setAudienceRestrictions(audiences);

        newEngine.processSecurityHeader(doc, data);
    }

    @Test
    public void testSAML2Delegate() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
        callbackHandler.setIssuer("www.example.com");

        ConditionsBean conditions = new ConditionsBean();
        DateTime notBefore = new DateTime();
        conditions.setNotBefore(notBefore);
        conditions.setNotAfter(notBefore.plusMinutes(20));

        DelegateBean delegate = new DelegateBean();
        delegate.setDelegationInstant(DateTime.now());
        delegate.setConfirmationMethod(SAML2Constants.CONF_BEARER);

        NameIDBean nameID = new NameIDBean();
        nameID.setNameValue("bob");
        nameID.setNameQualifier("www.example.com");
        delegate.setNameIDBean(nameID);

        conditions.setDelegates(Collections.singletonList(delegate));

        callbackHandler.setConditions(conditions);

        createAndVerifyMessage(callbackHandler, true);
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