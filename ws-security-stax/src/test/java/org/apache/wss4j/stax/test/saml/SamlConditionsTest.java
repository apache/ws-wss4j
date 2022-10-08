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
package org.apache.wss4j.stax.test.saml;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Properties;

import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.XMLStreamWriter;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import net.shibboleth.shared.xml.DOMTypeSupport;
import org.apache.wss4j.common.saml.bean.AudienceRestrictionBean;
import org.apache.wss4j.common.saml.bean.ConditionsBean;
import org.apache.wss4j.common.saml.bean.ProxyRestrictionBean;
import org.apache.wss4j.common.saml.builder.SAML1Constants;
import org.apache.wss4j.dom.handler.WSHandlerConstants;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.ext.WSSSecurityProperties;
import org.apache.wss4j.stax.setup.InboundWSSec;
import org.apache.wss4j.stax.setup.OutboundWSSec;
import org.apache.wss4j.stax.setup.WSSec;
import org.apache.wss4j.stax.test.AbstractTestBase;
import org.apache.wss4j.stax.test.CallbackHandlerImpl;
import org.apache.wss4j.stax.test.utils.StAX2DOM;
import org.apache.wss4j.stax.test.utils.XmlReaderToWriter;
import org.apache.xml.security.stax.securityEvent.SecurityEvent;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;

public class SamlConditionsTest extends AbstractTestBase {

    /**
     * Test that creates, sends and processes an unsigned SAML 1.1 authentication assertion
     * with a custom Conditions statement.
     */
    @Test
    public void testSAML1ConditionsOutbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            List<WSSConstants.Action> actions = new ArrayList<>();
            actions.add(WSSConstants.SAML_TOKEN_SIGNED);
            securityProperties.setActions(actions);
            SAMLCallbackHandlerImpl callbackHandler = new SAMLCallbackHandlerImpl();
            callbackHandler.setStatement(SAMLCallbackHandlerImpl.Statement.AUTHN);
            callbackHandler.setIssuer("www.example.com");

            ConditionsBean conditions = new ConditionsBean();
            Instant notBefore = Instant.now();
            conditions.setNotBefore(notBefore);
            Instant notAfter = notBefore.plus(Duration.ofMinutes(20));
            conditions.setNotAfter(notAfter);
            callbackHandler.setConditions(conditions);

            securityProperties.setSamlCallbackHandler(callbackHandler);
            securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setSignatureUser("transmitter");
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, StandardCharsets.UTF_8.name(), new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            assertEquals(nodeList.getLength(), 2);
            assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_SAML_ASSERTION.getLocalPart());
            assertEquals(nodeList.item(1).getParentNode().getLocalName(), WSSConstants.TAG_WSSE_SECURITY.getLocalPart());

            nodeList = document.getElementsByTagNameNS("urn:oasis:names:tc:SAML:1.0:assertion", "Conditions");
            assertEquals(nodeList.getLength(), 1);
            assertEquals(((Element) nodeList.item(0)).getAttributeNS(null, "NotBefore"), DOMTypeSupport.instantToString(notBefore));
            assertEquals(((Element) nodeList.item(0)).getAttributeNS(null, "NotOnOrAfter"), DOMTypeSupport.instantToString(notAfter));
        }

        //done signature; now test sig-verification:
        {
            String action = WSHandlerConstants.SIGNATURE + " " + WSHandlerConstants.SAML_TOKEN_SIGNED;
            Properties properties = new Properties();
            doInboundSecurityWithWSS4J_1(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action, properties, false);
        }
    }

    /**
     * Test that creates, sends and processes an unsigned SAML 1.1 authentication assertion
     * with a custom Conditions statement.
     */
    @Test
    public void testSAML1ConditionsInbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
            callbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHN);
            callbackHandler.setConfirmationMethod(SAML1Constants.CONF_HOLDER_KEY);
            callbackHandler.setIssuer("www.example.com");

            ConditionsBean conditions = new ConditionsBean();
            Instant notBefore = Instant.now();
            conditions.setNotBefore(notBefore);
            Instant notAfter = notBefore.plus(Duration.ofMinutes(20));
            conditions.setNotAfter(notAfter);
            callbackHandler.setConditions(conditions);

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.SAML_TOKEN_SIGNED;
            Properties properties = new Properties();
            properties.put(WSHandlerConstants.SAML_CALLBACK_REF, callbackHandler);
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            assertEquals(nodeList.getLength(), 2);
            assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_SAML_ASSERTION.getLocalPart());
            assertEquals(nodeList.item(1).getParentNode().getLocalName(), WSSConstants.TAG_WSSE_SECURITY.getLocalPart());

            nodeList = securedDocument.getElementsByTagNameNS("urn:oasis:names:tc:SAML:1.0:assertion", "Conditions");
            assertEquals(nodeList.getLength(), 1);
            assertEquals(((Element) nodeList.item(0)).getAttributeNS(null, "NotBefore"), DOMTypeSupport.instantToString(notBefore));
            assertEquals(((Element) nodeList.item(0)).getAttributeNS(null, "NotOnOrAfter"), DOMTypeSupport.instantToString(notAfter));

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        //done signature; now test sig-verification:
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);
            assertNotNull(document);
        }
    }

    /**
     * Test that creates, sends and processes an unsigned SAML 2 authentication assertion
     * with an (invalid) custom Conditions statement.
     */
    @Test
    public void testSAML2InvalidAfterConditionsInbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
            callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
            callbackHandler.setIssuer("www.example.com");

            ConditionsBean conditions = new ConditionsBean();
            Instant notBefore = Instant.now();
            conditions.setNotBefore(notBefore.minus(Duration.ofMinutes(5)));
            conditions.setNotAfter(notBefore.minus(Duration.ofMinutes(3)));
            callbackHandler.setConditions(conditions);

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.SAML_TOKEN_SIGNED;
            Properties properties = new Properties();
            properties.put(WSHandlerConstants.SAML_CALLBACK_REF, callbackHandler);
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        //done signature; now test sig-verification:
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            try {
                StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);
                fail("XMLStreamException expected");
            } catch (XMLStreamException e) {
                assertNotNull(e.getCause());
            }
        }
    }

    @Test
    public void testSAML2StaleNotOnOrAfter() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
            callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
            callbackHandler.setIssuer("www.example.com");

            ConditionsBean conditions = new ConditionsBean();
            Instant notBefore = Instant.now();
            conditions.setNotAfter(notBefore.minus(Duration.ofMinutes(60)));
            conditions.setNotBefore(notBefore.minus(Duration.ofMinutes(70)));
            callbackHandler.setConditions(conditions);

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.SAML_TOKEN_SIGNED;
            Properties properties = new Properties();
            properties.put(WSHandlerConstants.SAML_CALLBACK_REF, callbackHandler);
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        //done signature; now test sig-verification:
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            try {
                StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);
                fail("XMLStreamException expected");
            } catch (XMLStreamException e) {
                assertNotNull(e.getCause());
            }
        }
    }

    @Test
    public void testSAML2FutureNotBefore() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
            callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
            callbackHandler.setIssuer("www.example.com");

            ConditionsBean conditions = new ConditionsBean();
            Instant notBefore = Instant.now();
            conditions.setNotAfter(notBefore.plus(Duration.ofMinutes(70)));
            conditions.setNotBefore(notBefore.plus(Duration.ofMinutes(60)));
            callbackHandler.setConditions(conditions);

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.SAML_TOKEN_SIGNED;
            Properties properties = new Properties();
            properties.put(WSHandlerConstants.SAML_CALLBACK_REF, callbackHandler);
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        //done signature; now test sig-verification:
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            try {
                StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);
                fail("XMLStreamException expected");
            } catch (XMLStreamException e) {
                assertNotNull(e.getCause());
            }
        }
    }

    /**
     * Test that creates, sends and processes an unsigned SAML 2 authentication assertion
     * with an (invalid) custom Conditions statement.
     */
    @Test
    public void testSAML2InvalidBeforeConditionsInbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
            callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
            callbackHandler.setIssuer("www.example.com");

            ConditionsBean conditions = new ConditionsBean();
            Instant notBefore = Instant.now();
            conditions.setNotBefore(notBefore.plus(Duration.ofMinutes(2)));
            conditions.setNotAfter(notBefore.plus(Duration.ofMinutes(5)));
            callbackHandler.setConditions(conditions);

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.SAML_TOKEN_SIGNED;
            Properties properties = new Properties();
            properties.put(WSHandlerConstants.SAML_CALLBACK_REF, callbackHandler);
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        //done signature; now test sig-verification:
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            try {
                StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);
                fail("XMLStreamException expected");
            } catch (XMLStreamException e) {
                assertNotNull(e.getCause());
            }
        }
    }

    /**
     * Test that creates, sends and processes an unsigned SAML 2 authentication assertion
     * with a Conditions statement that has a NotBefore "in the future".
     */
    @Test
    public void testSAML2FutureTTLConditions() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
            callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
            callbackHandler.setIssuer("www.example.com");

            ConditionsBean conditions = new ConditionsBean();
            Instant notBefore = Instant.now();
            conditions.setNotBefore(notBefore.plusSeconds(30));
            conditions.setNotAfter(notBefore.plus(Duration.ofMinutes(5)));
            callbackHandler.setConditions(conditions);

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.SAML_TOKEN_SIGNED;
            Properties properties = new Properties();
            properties.put(WSHandlerConstants.SAML_CALLBACK_REF, callbackHandler);
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        //done signature; now test sig-verification:
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);
            assertNotNull(document);
        }
    }

    /**
     * Test that creates, sends and processes an unsigned SAML 2 authentication assertion
     * with a OneTimeUse Element
     */
    @Test
    public void testSAML2OneTimeUse() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
            callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
            callbackHandler.setIssuer("www.example.com");

            ConditionsBean conditions = new ConditionsBean();
            conditions.setTokenPeriodMinutes(5);
            conditions.setOneTimeUse(true);

            callbackHandler.setConditions(conditions);

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.SAML_TOKEN_SIGNED;
            Properties properties = new Properties();
            properties.put(WSHandlerConstants.SAML_CALLBACK_REF, callbackHandler);
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        //done signature; now test sig-verification:
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);
            assertNotNull(document);
        }
    }

    /**
     * Test that creates, sends and processes an unsigned SAML 2 authentication assertion
     * with a ProxyRestriction Element
     */
    @Test
    public void testSAML2ProxyRestriction() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
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

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.SAML_TOKEN_SIGNED;
            Properties properties = new Properties();
            properties.put(WSHandlerConstants.SAML_CALLBACK_REF, callbackHandler);
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        //done signature; now test sig-verification:
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);
            assertNotNull(document);
        }
    }

    /**
     * Test that creates, sends and processes an unsigned SAML 2 authentication assertion
     * with an AudienceRestriction Element
     */
    @Test
    public void testSAML2AudienceRestriction() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
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

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.SAML_TOKEN_SIGNED;
            Properties properties = new Properties();
            properties.put(WSHandlerConstants.SAML_CALLBACK_REF, callbackHandler);
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        //done signature; now test sig-verification:
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);
            assertNotNull(document);
        }
    }

    // Now test AudienceRestrictions with supplied restrictions
    @Test
    public void testSAML2AudienceRestrictionValidation() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        List<String> audiences = new ArrayList<>();
        {
            SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
            callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
            callbackHandler.setIssuer("www.example.com");

            ConditionsBean conditions = new ConditionsBean();
            conditions.setTokenPeriodMinutes(5);
            audiences.add("http://apache.org/one");
            audiences.add("http://apache.org/two");
            AudienceRestrictionBean audienceRestrictionBean = new AudienceRestrictionBean();
            audienceRestrictionBean.setAudienceURIs(audiences);
            conditions.setAudienceRestrictions(Collections.singletonList(audienceRestrictionBean));

            callbackHandler.setConditions(conditions);

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.SAML_TOKEN_SIGNED;
            Properties properties = new Properties();
            properties.put(WSHandlerConstants.SAML_CALLBACK_REF, callbackHandler);
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        // This should fail as the expected audience isn't in the assertion
        audiences.clear();
        audiences.add("http://apache.org/three");
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setAudienceRestrictions(audiences);
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            try {
                StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);
                fail("XMLStreamException expected");
            } catch (XMLStreamException e) {
                assertNotNull(e.getCause());
            }
        }

        // Now add the correct audience back in...
        audiences.add("http://apache.org/one");
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setAudienceRestrictions(audiences);
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);
            assertNotNull(document);
        }
    }

    // Now test AudienceRestrictions with supplied restrictions
    @Test
    public void testSAML1AudienceRestrictionValidation() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        List<String> audiences = new ArrayList<>();
        {
            SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
            callbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHN);
            callbackHandler.setIssuer("www.example.com");

            ConditionsBean conditions = new ConditionsBean();
            conditions.setTokenPeriodMinutes(5);
            audiences.add("http://apache.org/one");
            audiences.add("http://apache.org/two");
            AudienceRestrictionBean audienceRestrictionBean = new AudienceRestrictionBean();
            audienceRestrictionBean.setAudienceURIs(audiences);
            conditions.setAudienceRestrictions(Collections.singletonList(audienceRestrictionBean));

            callbackHandler.setConditions(conditions);

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.SAML_TOKEN_SIGNED;
            Properties properties = new Properties();
            properties.put(WSHandlerConstants.SAML_CALLBACK_REF, callbackHandler);
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        // This should fail as the expected audience isn't in the assertion
        audiences.clear();
        audiences.add("http://apache.org/three");
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setAudienceRestrictions(audiences);
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            try {
                StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);
                fail("XMLStreamException expected");
            } catch (XMLStreamException e) {
                assertNotNull(e.getCause());
            }
        }

        // Now add the correct audience back in...
        audiences.add("http://apache.org/one");
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setAudienceRestrictions(audiences);
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);
            assertNotNull(document);
        }
    }

    /**
     * Test that creates, sends and processes an unsigned SAML 2 authentication assertion
     * with two AudienceRestriction Elements
     */
    @Test
    public void testSAML2AudienceRestrictionSeparateRestrictions() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
            callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
            callbackHandler.setIssuer("www.example.com");

            ConditionsBean conditions = new ConditionsBean();
            conditions.setTokenPeriodMinutes(5);

            List<AudienceRestrictionBean> audiencesRestrictions =
                new ArrayList<>();
            AudienceRestrictionBean audienceRestrictionBean = new AudienceRestrictionBean();
            audienceRestrictionBean.setAudienceURIs(Collections.singletonList("http://apache.org/one"));
            audiencesRestrictions.add(audienceRestrictionBean);

            audienceRestrictionBean = new AudienceRestrictionBean();
            audienceRestrictionBean.setAudienceURIs(Collections.singletonList("http://apache.org/two"));
            audiencesRestrictions.add(audienceRestrictionBean);

            conditions.setAudienceRestrictions(audiencesRestrictions);

            callbackHandler.setConditions(conditions);

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.SAML_TOKEN_SIGNED;
            Properties properties = new Properties();
            properties.put(WSHandlerConstants.SAML_CALLBACK_REF, callbackHandler);
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        //done signature; now test sig-verification:
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);
            assertNotNull(document);
        }
    }

    // Now test AudienceRestrictions with supplied restrictions
    @Test
    public void testSAML1AudienceRestrictionSeparateRestrictionsValidation() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
            callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
            callbackHandler.setIssuer("www.example.com");

            ConditionsBean conditions = new ConditionsBean();
            conditions.setTokenPeriodMinutes(5);

            List<AudienceRestrictionBean> audiencesRestrictions =
                new ArrayList<>();
            AudienceRestrictionBean audienceRestrictionBean = new AudienceRestrictionBean();
            audienceRestrictionBean.setAudienceURIs(Collections.singletonList("http://apache.org/one"));
            audiencesRestrictions.add(audienceRestrictionBean);

            audienceRestrictionBean = new AudienceRestrictionBean();
            audienceRestrictionBean.setAudienceURIs(Collections.singletonList("http://apache.org/two"));
            audiencesRestrictions.add(audienceRestrictionBean);

            conditions.setAudienceRestrictions(audiencesRestrictions);

            callbackHandler.setConditions(conditions);

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.SAML_TOKEN_SIGNED;
            Properties properties = new Properties();
            properties.put(WSHandlerConstants.SAML_CALLBACK_REF, callbackHandler);
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        // This should fail as the expected audience isn't in the assertion
        List<String> audiences = new ArrayList<>();
        audiences.add("http://apache.org/three");
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setAudienceRestrictions(audiences);
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            try {
                StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);
                fail("XMLStreamException expected");
            } catch (XMLStreamException e) {
                assertNotNull(e.getCause());
            }
        }

        // Now add the correct audience back in...
        audiences.add("http://apache.org/one");
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setAudienceRestrictions(audiences);
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);
            assertNotNull(document);
        }
    }
}