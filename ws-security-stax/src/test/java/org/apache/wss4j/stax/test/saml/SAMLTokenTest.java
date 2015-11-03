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
import java.security.Key;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.XMLStreamWriter;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.wss4j.common.ConfigurationConstants;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.crypto.CryptoType;
import org.apache.wss4j.common.saml.SAMLCallback;
import org.apache.wss4j.common.saml.SAMLUtil;
import org.apache.wss4j.common.saml.SamlAssertionWrapper;
import org.apache.wss4j.common.saml.bean.Version;
import org.apache.wss4j.common.saml.builder.SAML1Constants;
import org.apache.wss4j.common.saml.builder.SAML2Constants;
import org.apache.wss4j.common.token.SecurityTokenReference;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.common.KeystoreCallbackHandler;
import org.apache.wss4j.dom.handler.WSHandlerConstants;
import org.apache.wss4j.dom.message.WSSecHeader;
import org.apache.wss4j.dom.message.WSSecSAMLToken;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.ext.WSSSecurityProperties;
import org.apache.wss4j.stax.setup.ConfigurationConverter;
import org.apache.wss4j.stax.setup.InboundWSSec;
import org.apache.wss4j.stax.setup.OutboundWSSec;
import org.apache.wss4j.stax.setup.WSSec;
import org.apache.wss4j.stax.test.AbstractTestBase;
import org.apache.wss4j.stax.test.utils.SOAPUtil;
import org.apache.wss4j.stax.test.utils.StAX2DOM;
import org.apache.wss4j.stax.test.utils.XmlReaderToWriter;
import org.apache.wss4j.stax.validate.SamlTokenValidatorImpl;
import org.apache.xml.security.encryption.EncryptedData;
import org.apache.xml.security.encryption.EncryptedKey;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.stax.securityEvent.SecurityEvent;
import org.joda.time.DateTime;
import org.junit.Assert;
import org.junit.Test;
import org.opensaml.core.xml.XMLObjectBuilder;
import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.schema.XSAny;
import org.opensaml.saml.common.SAMLObjectBuilder;
import org.opensaml.saml.saml2.core.AttributeValue;
import org.opensaml.saml.saml2.core.Conditions;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

public class SAMLTokenTest extends AbstractTestBase {

    @Test
    public void testSAML1AuthnAssertionOutbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            List<WSSConstants.Action> actions = new ArrayList<WSSConstants.Action>();
            actions.add(WSSConstants.SAML_TOKEN_UNSIGNED);
            securityProperties.setActions(actions);
            SAMLCallbackHandlerImpl callbackHandler = new SAMLCallbackHandlerImpl();
            callbackHandler.setStatement(SAMLCallbackHandlerImpl.Statement.AUTHN);
            callbackHandler.setIssuer("www.example.com");
            callbackHandler.setSignAssertion(false);
            securityProperties.setSamlCallbackHandler(callbackHandler);

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, StandardCharsets.UTF_8.name(), new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 0);
        }

        //done signature; now test sig-verification:
        {
            String action = WSHandlerConstants.SAML_TOKEN_UNSIGNED;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @Test
    public void testSAML1AuthnAssertionInbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
            callbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHN);
            callbackHandler.setIssuer("www.example.com");
            callbackHandler.setSignAssertion(false);

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.SAML_TOKEN_UNSIGNED + " " + WSHandlerConstants.SIGNATURE;
            Properties properties = new Properties();
            properties.put(WSHandlerConstants.SAML_CALLBACK_REF, callbackHandler);
            properties.setProperty(WSHandlerConstants.SIGNATURE_PARTS, "{Element}{urn:oasis:names:tc:SAML:1.0:assertion}Assertion;{Element}{http://schemas.xmlsoap.org/soap/envelope/}Body;");
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        //done signature; now test sig-verification:
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setSamlCallbackHandler(new SAMLCallbackHandlerImpl());
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
        }
    }

    @Test
    public void testSAML1AttrAssertionOutbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            List<WSSConstants.Action> actions = new ArrayList<WSSConstants.Action>();
            actions.add(WSSConstants.SAML_TOKEN_UNSIGNED);
            securityProperties.setActions(actions);
            SAMLCallbackHandlerImpl callbackHandler = new SAMLCallbackHandlerImpl();
            callbackHandler.setStatement(SAMLCallbackHandlerImpl.Statement.ATTR);
            callbackHandler.setIssuer("www.example.com");
            callbackHandler.setSignAssertion(false);
            securityProperties.setSamlCallbackHandler(callbackHandler);

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, StandardCharsets.UTF_8.name(), new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 0);
        }

        //done signature; now test sig-verification:
        {
            String action = WSHandlerConstants.SAML_TOKEN_UNSIGNED;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @Test
    public void testSAML1AttrAssertionInbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
            callbackHandler.setStatement(SAML1CallbackHandler.Statement.ATTR);
            callbackHandler.setIssuer("www.example.com");
            callbackHandler.setSignAssertion(false);

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.SAML_TOKEN_UNSIGNED + " " + WSHandlerConstants.SIGNATURE;
            Properties properties = new Properties();
            properties.put(WSHandlerConstants.SAML_CALLBACK_REF, callbackHandler);
            properties.setProperty(WSHandlerConstants.SIGNATURE_PARTS, "{Element}{urn:oasis:names:tc:SAML:1.0:assertion}Assertion;{Element}{http://schemas.xmlsoap.org/soap/envelope/}Body;");
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        //done signature; now test sig-verification:
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setSamlCallbackHandler(new SAMLCallbackHandlerImpl());
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
        }
    }

    @Test
    public void testSAML1AuthzAssertionOutbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            List<WSSConstants.Action> actions = new ArrayList<WSSConstants.Action>();
            actions.add(WSSConstants.SAML_TOKEN_UNSIGNED);
            securityProperties.setActions(actions);
            SAMLCallbackHandlerImpl callbackHandler = new SAMLCallbackHandlerImpl();
            callbackHandler.setStatement(SAMLCallbackHandlerImpl.Statement.AUTHZ);
            callbackHandler.setIssuer("www.example.com");
            callbackHandler.setSignAssertion(false);
            callbackHandler.setResource("http://resource.org");
            securityProperties.setSamlCallbackHandler(callbackHandler);

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, StandardCharsets.UTF_8.name(), new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 0);
        }

        //done signature; now test sig-verification:
        {
            String action = WSHandlerConstants.SAML_TOKEN_UNSIGNED;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @Test
    public void testSAML1AuthzAssertionInbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
            callbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHZ);
            callbackHandler.setIssuer("www.example.com");
            callbackHandler.setResource("http://resource.org");
            callbackHandler.setSignAssertion(false);

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.SAML_TOKEN_UNSIGNED + " " + WSHandlerConstants.SIGNATURE;
            Properties properties = new Properties();
            properties.put(WSHandlerConstants.SAML_CALLBACK_REF, callbackHandler);
            properties.setProperty(WSHandlerConstants.SIGNATURE_PARTS, "{Element}{urn:oasis:names:tc:SAML:1.0:assertion}Assertion;{Element}{http://schemas.xmlsoap.org/soap/envelope/}Body;");
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        //done signature; now test sig-verification:
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setSamlCallbackHandler(new SAMLCallbackHandlerImpl());
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
        }
    }

    @Test
    public void testSAML2AuthnAssertionOutbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            List<WSSConstants.Action> actions = new ArrayList<WSSConstants.Action>();
            actions.add(WSSConstants.SAML_TOKEN_UNSIGNED);
            securityProperties.setActions(actions);
            SAMLCallbackHandlerImpl callbackHandler = new SAMLCallbackHandlerImpl();
            callbackHandler.setSamlVersion(Version.SAML_20);
            callbackHandler.setStatement(SAMLCallbackHandlerImpl.Statement.AUTHN);
            callbackHandler.setIssuer("www.example.com");
            callbackHandler.setSignAssertion(false);
            securityProperties.setSamlCallbackHandler(callbackHandler);

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, StandardCharsets.UTF_8.name(), new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 0);
        }

        //done signature; now test sig-verification:
        {
            String action = WSHandlerConstants.SAML_TOKEN_UNSIGNED;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @Test
    public void testSAML2AuthnAssertionInbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
            callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
            callbackHandler.setIssuer("www.example.com");
            callbackHandler.setSignAssertion(false);

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.SAML_TOKEN_UNSIGNED + " " + WSHandlerConstants.SIGNATURE;
            Properties properties = new Properties();
            properties.put(WSHandlerConstants.SAML_CALLBACK_REF, callbackHandler);
            properties.setProperty(WSHandlerConstants.SIGNATURE_PARTS, "{Element}{urn:oasis:names:tc:SAML:2.0:assertion}Assertion;{Element}{http://schemas.xmlsoap.org/soap/envelope/}Body;");
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        //done signature; now test sig-verification:
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setSamlCallbackHandler(new SAMLCallbackHandlerImpl());
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
        }
    }

    @Test
    public void testSAML2AttrAssertionOutbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            List<WSSConstants.Action> actions = new ArrayList<WSSConstants.Action>();
            actions.add(WSSConstants.SAML_TOKEN_UNSIGNED);
            securityProperties.setActions(actions);
            SAMLCallbackHandlerImpl callbackHandler = new SAMLCallbackHandlerImpl();
            callbackHandler.setSamlVersion(Version.SAML_20);
            callbackHandler.setStatement(SAMLCallbackHandlerImpl.Statement.ATTR);
            callbackHandler.setIssuer("www.example.com");
            callbackHandler.setSignAssertion(false);
            securityProperties.setSamlCallbackHandler(callbackHandler);

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, StandardCharsets.UTF_8.name(), new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 0);
        }

        //done signature; now test sig-verification:
        {
            String action = WSHandlerConstants.SAML_TOKEN_UNSIGNED;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @Test
    public void testSAML2AttrAssertionInbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
            callbackHandler.setStatement(SAML2CallbackHandler.Statement.ATTR);
            callbackHandler.setIssuer("www.example.com");
            callbackHandler.setSignAssertion(false);

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.SAML_TOKEN_UNSIGNED + " " + WSHandlerConstants.SIGNATURE;
            Properties properties = new Properties();
            properties.put(WSHandlerConstants.SAML_CALLBACK_REF, callbackHandler);
            properties.setProperty(WSHandlerConstants.SIGNATURE_PARTS, "{Element}{urn:oasis:names:tc:SAML:2.0:assertion}Assertion;{Element}{http://schemas.xmlsoap.org/soap/envelope/}Body;");
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        //done signature; now test sig-verification:
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setSamlCallbackHandler(new SAMLCallbackHandlerImpl());
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
        }
    }

    @Test
    public void testSAML2AuthzAssertionOutbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            List<WSSConstants.Action> actions = new ArrayList<WSSConstants.Action>();
            actions.add(WSSConstants.SAML_TOKEN_UNSIGNED);
            securityProperties.setActions(actions);
            SAMLCallbackHandlerImpl callbackHandler = new SAMLCallbackHandlerImpl();
            callbackHandler.setSamlVersion(Version.SAML_20);
            callbackHandler.setStatement(SAMLCallbackHandlerImpl.Statement.AUTHZ);
            callbackHandler.setIssuer("www.example.com");
            callbackHandler.setSignAssertion(false);
            callbackHandler.setResource("http://resource.org");
            securityProperties.setSamlCallbackHandler(callbackHandler);

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, StandardCharsets.UTF_8.name(), new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 0);
        }

        //done signature; now test sig-verification:
        {
            String action = WSHandlerConstants.SAML_TOKEN_UNSIGNED;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @Test
    public void testSAML2AuthzAssertionInbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
            callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHZ);
            callbackHandler.setIssuer("www.example.com");
            callbackHandler.setResource("http://resource.org");
            callbackHandler.setSignAssertion(false);

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.SAML_TOKEN_UNSIGNED + " " + WSHandlerConstants.SIGNATURE;
            Properties properties = new Properties();
            properties.put(WSHandlerConstants.SAML_CALLBACK_REF, callbackHandler);
            properties.setProperty(WSHandlerConstants.SIGNATURE_PARTS, "{Element}{urn:oasis:names:tc:SAML:2.0:assertion}Assertion;{Element}{http://schemas.xmlsoap.org/soap/envelope/}Body;");
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        //done signature; now test sig-verification:
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setSamlCallbackHandler(new SAMLCallbackHandlerImpl());
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
        }
    }

    /**
     * Test that creates, sends and processes an unsigned SAML 1.1 authentication assertion with
     * a user-specified SubjectNameIDFormat.
     */
    @Test
    public void testSAML1SubjectNameIDFormatOutbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            List<WSSConstants.Action> actions = new ArrayList<WSSConstants.Action>();
            actions.add(WSSConstants.SAML_TOKEN_UNSIGNED);
            securityProperties.setActions(actions);
            SAMLCallbackHandlerImpl callbackHandler = new SAMLCallbackHandlerImpl();
            callbackHandler.setStatement(SAMLCallbackHandlerImpl.Statement.AUTHN);
            callbackHandler.setIssuer("www.example.com");
            callbackHandler.setSignAssertion(false);
            callbackHandler.setSubjectNameIDFormat(SAML1Constants.NAMEID_FORMAT_EMAIL_ADDRESS);
            securityProperties.setSamlCallbackHandler(callbackHandler);

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, StandardCharsets.UTF_8.name(), new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 0);
        }

        //done signature; now test sig-verification:
        {
            String action = WSHandlerConstants.SAML_TOKEN_UNSIGNED;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    /**
     * Test that creates, sends and processes an unsigned SAML 2 authentication assertion with
     * a user-specified SubjectNameIDFormat.
     */
    @Test
    public void testSAML2SubjectNameIDFormatOutbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            List<WSSConstants.Action> actions = new ArrayList<WSSConstants.Action>();
            actions.add(WSSConstants.SAML_TOKEN_UNSIGNED);
            securityProperties.setActions(actions);
            SAMLCallbackHandlerImpl callbackHandler = new SAMLCallbackHandlerImpl();
            callbackHandler.setStatement(SAMLCallbackHandlerImpl.Statement.AUTHN);
            callbackHandler.setSamlVersion(Version.SAML_20);
            callbackHandler.setIssuer("www.example.com");
            callbackHandler.setSignAssertion(false);
            callbackHandler.setSubjectNameIDFormat(SAML1Constants.NAMEID_FORMAT_EMAIL_ADDRESS);
            securityProperties.setSamlCallbackHandler(callbackHandler);

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, StandardCharsets.UTF_8.name(), new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 0);
        }

        //done signature; now test sig-verification:
        {
            String action = WSHandlerConstants.SAML_TOKEN_UNSIGNED;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    /**
     * Test that creates, sends and processes an unsigned SAML 1.1 authentication assertion with
     * a user-specified SubjectLocality statement.
     */
    @Test
    public void testSAML1SubjectLocalityOutbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            List<WSSConstants.Action> actions = new ArrayList<WSSConstants.Action>();
            actions.add(WSSConstants.SAML_TOKEN_UNSIGNED);
            securityProperties.setActions(actions);
            SAMLCallbackHandlerImpl callbackHandler = new SAMLCallbackHandlerImpl();
            callbackHandler.setStatement(SAMLCallbackHandlerImpl.Statement.AUTHN);
            callbackHandler.setIssuer("www.example.com");
            callbackHandler.setSignAssertion(false);
            callbackHandler.setSubjectLocality("12.34.56.78", "test-dns");
            securityProperties.setSamlCallbackHandler(callbackHandler);

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, StandardCharsets.UTF_8.name(), new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 0);
        }

        //done signature; now test sig-verification:
        {
            String action = WSHandlerConstants.SAML_TOKEN_UNSIGNED;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    /**
     * Test that creates, sends and processes an unsigned SAML 2 authentication assertion with
     * a user-specified SubjectLocality statement.
     */
    @Test
    public void testSAML2SubjectLocalityOutbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            List<WSSConstants.Action> actions = new ArrayList<WSSConstants.Action>();
            actions.add(WSSConstants.SAML_TOKEN_UNSIGNED);
            securityProperties.setActions(actions);
            SAMLCallbackHandlerImpl callbackHandler = new SAMLCallbackHandlerImpl();
            callbackHandler.setStatement(SAMLCallbackHandlerImpl.Statement.AUTHN);
            callbackHandler.setIssuer("www.example.com");
            callbackHandler.setSignAssertion(false);
            callbackHandler.setSamlVersion(Version.SAML_20);
            callbackHandler.setSubjectLocality("12.34.56.78", "test-dns");
            securityProperties.setSamlCallbackHandler(callbackHandler);

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, StandardCharsets.UTF_8.name(), new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 0);
        }

        //done signature; now test sig-verification:
        {
            String action = WSHandlerConstants.SAML_TOKEN_UNSIGNED;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    /**
     * Test that creates, sends and processes an unsigned SAML 1.1 authz assertion with
     * a Resource URI
     */
    @Test
    public void testSAML1ResourceOutbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            List<WSSConstants.Action> actions = new ArrayList<WSSConstants.Action>();
            actions.add(WSSConstants.SAML_TOKEN_UNSIGNED);
            securityProperties.setActions(actions);
            SAMLCallbackHandlerImpl callbackHandler = new SAMLCallbackHandlerImpl();
            callbackHandler.setStatement(SAMLCallbackHandlerImpl.Statement.AUTHZ);
            callbackHandler.setIssuer("www.example.com");
            callbackHandler.setResource("http://resource.org");
            callbackHandler.setSignAssertion(false);
            securityProperties.setSamlCallbackHandler(callbackHandler);

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, StandardCharsets.UTF_8.name(), new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 0);
        }

        //done signature; now test sig-verification:
        {
            String action = WSHandlerConstants.SAML_TOKEN_UNSIGNED;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }


    /**
     * Test that creates, sends and processes an unsigned SAML 2 attribute assertion. The attributeValue
     * has a custom XMLObject (not a String) value.
     */
    @Test
    @SuppressWarnings("unchecked")
    public void testSAML2AttrAssertionCustomAttributeOutbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            List<WSSConstants.Action> actions = new ArrayList<WSSConstants.Action>();
            actions.add(WSSConstants.SAML_TOKEN_UNSIGNED);
            securityProperties.setActions(actions);
            SAMLCallbackHandlerImpl callbackHandler = new SAMLCallbackHandlerImpl();
            callbackHandler.setStatement(SAMLCallbackHandlerImpl.Statement.ATTR);
            callbackHandler.setIssuer("www.example.com");
            callbackHandler.setSignAssertion(false);
            callbackHandler.setSamlVersion(Version.SAML_20);

            // Create and add a custom Attribute (conditions Object)
            XMLObjectBuilderFactory builderFactory = XMLObjectProviderRegistrySupport.getBuilderFactory();

            SAMLObjectBuilder<Conditions> conditionsV2Builder =
                    (SAMLObjectBuilder<Conditions>) builderFactory.getBuilder(Conditions.DEFAULT_ELEMENT_NAME);
            Conditions conditions = conditionsV2Builder.buildObject();
            DateTime newNotBefore = new DateTime();
            conditions.setNotBefore(newNotBefore);
            conditions.setNotOnOrAfter(newNotBefore.plusMinutes(5));

            XMLObjectBuilder<XSAny> xsAnyBuilder = 
                (XMLObjectBuilder<XSAny>)builderFactory.getBuilder(XSAny.TYPE_NAME);
            XSAny attributeValue = xsAnyBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME);
            attributeValue.getUnknownXMLObjects().add(conditions);

            List<Object> attributeValues = new ArrayList<Object>();
            attributeValues.add(attributeValue);
            callbackHandler.setCustomAttributeValues(attributeValues);
            
            securityProperties.setSamlCallbackHandler(callbackHandler);

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, StandardCharsets.UTF_8.name(), new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 0);
        }

        //done signature; now test sig-verification:
        {
            String action = WSHandlerConstants.SAML_TOKEN_UNSIGNED;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @Test
    public void testSAML1AuthnAssertionPropertiesOutbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            Map<String, Object> config = new HashMap<String, Object>();
            config.put(ConfigurationConstants.ACTION, ConfigurationConstants.SAML_TOKEN_UNSIGNED);

            SAMLCallbackHandlerImpl callbackHandler = new SAMLCallbackHandlerImpl();
            callbackHandler.setStatement(SAMLCallbackHandlerImpl.Statement.AUTHN);
            callbackHandler.setIssuer("www.example.com");
            callbackHandler.setSignAssertion(false);
            config.put(ConfigurationConstants.SAML_CALLBACK_REF, callbackHandler);

            WSSSecurityProperties securityProperties = ConfigurationConverter.convert(config);
            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, StandardCharsets.UTF_8.name(), new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 0);
        }

        //done signature; now test sig-verification:
        {
            String action = WSHandlerConstants.SAML_TOKEN_UNSIGNED;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @Test
    public void testSAML1AuthnAssertionPropertiesInbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
            callbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHN);
            callbackHandler.setIssuer("www.example.com");
            callbackHandler.setSignAssertion(false);

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.SAML_TOKEN_UNSIGNED + " " + WSHandlerConstants.SIGNATURE;
            Properties properties = new Properties();
            properties.put(WSHandlerConstants.SAML_CALLBACK_REF, callbackHandler);
            properties.setProperty(WSHandlerConstants.SIGNATURE_PARTS, "{Element}{urn:oasis:names:tc:SAML:1.0:assertion}Assertion;{Element}{http://schemas.xmlsoap.org/soap/envelope/}Body;");
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        //done signature; now test sig-verification:
        {
            Map<String, Object> config = new HashMap<String, Object>();
            config.put(ConfigurationConstants.ACTION, ConfigurationConstants.SAML_TOKEN_UNSIGNED);
            config.put(ConfigurationConstants.SIG_VER_PROP_FILE, "receiver-crypto.properties");

            WSSSecurityProperties securityProperties = ConfigurationConverter.convert(config);
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
        }
    }
    
    /**
     * Test that creates, sends and processes an unsigned SAML 2 authentication assertion, which
     * is encrypted in a saml2:EncryptedAssertion Element in the security header
     */
    @org.junit.Test
    public void testSAML2EncryptedAssertion() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        Crypto crypto = CryptoFactory.getInstance("wss40.properties");
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            
            SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
            callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
            callbackHandler.setIssuer("www.example.com");
            
            SAMLCallback samlCallback = new SAMLCallback();
            SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
            SamlAssertionWrapper samlAssertion = new SamlAssertionWrapper(samlCallback);

            WSSecSAMLToken wsSign = new WSSecSAMLToken();

            Document doc = SOAPUtil.toSOAPPart(sourceDocument);
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
            CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
            cryptoType.setAlias("wss40");
            X509Certificate[] certs = crypto.getX509Certificates(cryptoType);
            assertTrue(certs != null && certs.length > 0 && certs[0] != null);
            
            encryptElement(doc, assertionElement, WSConstants.AES_128, secretKey,
                    WSConstants.KEYTRANSPORT_RSAOEP, certs[0], false);
            
            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(doc), new StreamResult(baos));
        }

        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.setDecryptionCrypto(crypto);
            securityProperties.setCallbackHandler(new KeystoreCallbackHandler());
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            // Decrypted Assertion element must be there
            NodeList nodeList = 
                document.getElementsByTagNameNS(WSSConstants.TAG_saml2_Assertion.getNamespaceURI(), WSSConstants.TAG_saml2_Assertion.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
        }
    }
    
    @Test
    public void testRequiredSubjectConfirmationMethod() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
            callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
            callbackHandler.setIssuer("www.example.com");
            callbackHandler.setSignAssertion(false);

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.SAML_TOKEN_UNSIGNED + " " + WSHandlerConstants.SIGNATURE;
            Properties properties = new Properties();
            properties.put(WSHandlerConstants.SAML_CALLBACK_REF, callbackHandler);
            properties.setProperty(WSHandlerConstants.SIGNATURE_PARTS, "{Element}{urn:oasis:names:tc:SAML:2.0:assertion}Assertion;{Element}{http://schemas.xmlsoap.org/soap/envelope/}Body;");
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        // Test that we have a SenderVouches assertion
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setSamlCallbackHandler(new SAMLCallbackHandlerImpl());
            
            SamlTokenValidatorImpl validator = new SamlTokenValidatorImpl();
            validator.setRequiredSubjectConfirmationMethod(SAML2Constants.CONF_SENDER_VOUCHES);
            securityProperties.addValidator(WSSConstants.TAG_saml2_Assertion, validator);
            securityProperties.addValidator(WSSConstants.TAG_saml_Assertion, validator);
            
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
        }
        
        baos = new ByteArrayOutputStream();
        // Now create a Bearer assertion
        {
            SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
            callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
            callbackHandler.setConfirmationMethod(SAML2Constants.CONF_BEARER);
            callbackHandler.setIssuer("www.example.com");
            callbackHandler.setSignAssertion(false);

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.SAML_TOKEN_UNSIGNED + " " + WSHandlerConstants.SIGNATURE;
            Properties properties = new Properties();
            properties.put(WSHandlerConstants.SAML_CALLBACK_REF, callbackHandler);
            properties.setProperty(WSHandlerConstants.SIGNATURE_PARTS, "{Element}{urn:oasis:names:tc:SAML:2.0:assertion}Assertion;{Element}{http://schemas.xmlsoap.org/soap/envelope/}Body;");
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        // Test that we have a SenderVouches assertion
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setSamlCallbackHandler(new SAMLCallbackHandlerImpl());
            
            SamlTokenValidatorImpl validator = new SamlTokenValidatorImpl();
            validator.setRequiredSubjectConfirmationMethod(SAML2Constants.CONF_SENDER_VOUCHES);
            securityProperties.addValidator(WSSConstants.TAG_saml2_Assertion, validator);
            securityProperties.addValidator(WSSConstants.TAG_saml_Assertion, validator);
            
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            try {
                StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);
                fail("Failure expected on a Bearer assertion");
            }  catch (XMLStreamException e) {
                // expected
            }
        }
    }
    
    @Test
    public void testStandardSubjectConfirmationMethod() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
            callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
            callbackHandler.setIssuer("www.example.com");
            callbackHandler.setConfirmationMethod("urn:oasis:names:tc:SAML:2.0:cm:custom");
            callbackHandler.setSignAssertion(false);

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.SAML_TOKEN_UNSIGNED + " " + WSHandlerConstants.SIGNATURE;
            Properties properties = new Properties();
            properties.put(WSHandlerConstants.SAML_CALLBACK_REF, callbackHandler);
            properties.setProperty(WSHandlerConstants.SIGNATURE_PARTS, "{Element}{urn:oasis:names:tc:SAML:2.0:assertion}Assertion;{Element}{http://schemas.xmlsoap.org/soap/envelope/}Body;");
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        // Validate
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setSamlCallbackHandler(new SAMLCallbackHandlerImpl());
            
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            try {
                StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);
                fail("Failure expected on an unknown subject confirmation method");
            }  catch (XMLStreamException e) {
                // expected
            }
        }
        
        // Validate again - disable the standard subject confirmation method check
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setSamlCallbackHandler(new SAMLCallbackHandlerImpl());
            
            SamlTokenValidatorImpl validator = new SamlTokenValidatorImpl();
            validator.setRequireStandardSubjectConfirmationMethod(false);
            securityProperties.addValidator(WSSConstants.TAG_saml2_Assertion, validator);
            securityProperties.addValidator(WSSConstants.TAG_saml_Assertion, validator);
            
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);
        }
    }
    
    @Test
    public void testUnsignedBearer() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
            callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
            callbackHandler.setIssuer("www.example.com");
            callbackHandler.setConfirmationMethod(SAML2Constants.CONF_BEARER);
            callbackHandler.setSignAssertion(false);

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.SAML_TOKEN_UNSIGNED + " " + WSHandlerConstants.SIGNATURE;
            Properties properties = new Properties();
            properties.put(WSHandlerConstants.SAML_CALLBACK_REF, callbackHandler);
            properties.setProperty(WSHandlerConstants.SIGNATURE_PARTS, "{Element}{urn:oasis:names:tc:SAML:2.0:assertion}Assertion;{Element}{http://schemas.xmlsoap.org/soap/envelope/}Body;");
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        // Validate
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setSamlCallbackHandler(new SAMLCallbackHandlerImpl());
            
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            try {
                StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);
                fail("Failure expected on an unsigned bearer token");
            }  catch (XMLStreamException e) {
                // expected
            }
        }
        
        // Validate again - disable the signed Bearer check
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setSamlCallbackHandler(new SAMLCallbackHandlerImpl());
            
            SamlTokenValidatorImpl validator = new SamlTokenValidatorImpl();
            validator.setRequireBearerSignature(false);
            securityProperties.addValidator(WSSConstants.TAG_saml2_Assertion, validator);
            securityProperties.addValidator(WSSConstants.TAG_saml_Assertion, validator);
            
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);
        }
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
}
