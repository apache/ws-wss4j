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
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.XMLStreamWriter;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.crypto.CryptoType;
import org.apache.wss4j.common.crypto.Merlin;
import org.apache.wss4j.common.saml.SAMLCallback;
import org.apache.wss4j.common.saml.SAMLUtil;
import org.apache.wss4j.common.saml.SamlAssertionWrapper;
import org.apache.wss4j.common.saml.bean.KeyInfoBean;
import org.apache.wss4j.common.saml.bean.Version;
import org.apache.wss4j.common.saml.builder.SAML1Constants;
import org.apache.wss4j.common.saml.builder.SAML2Constants;
import org.apache.wss4j.dom.handler.WSHandlerConstants;
import org.apache.wss4j.dom.message.WSSecHeader;
import org.apache.wss4j.dom.message.WSSecSAMLToken;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.ext.WSSSecurityProperties;
import org.apache.wss4j.stax.impl.securityToken.HttpsSecurityTokenImpl;
import org.apache.wss4j.stax.securityEvent.HttpsTokenSecurityEvent;
import org.apache.wss4j.stax.securityToken.HttpsSecurityToken;
import org.apache.wss4j.stax.securityToken.WSSecurityTokenConstants;
import org.apache.wss4j.stax.setup.InboundWSSec;
import org.apache.wss4j.stax.setup.OutboundWSSec;
import org.apache.wss4j.stax.setup.WSSec;
import org.apache.wss4j.stax.test.AbstractTestBase;
import org.apache.wss4j.stax.test.CallbackHandlerImpl;
import org.apache.wss4j.stax.test.utils.SOAPUtil;
import org.apache.wss4j.stax.test.utils.StAX2DOM;
import org.apache.wss4j.stax.test.utils.XmlReaderToWriter;
import org.apache.xml.security.stax.securityEvent.SecurityEvent;
import org.junit.Assert;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

public class SAMLTokenHOKTest extends AbstractTestBase {

    @Test
    public void testSAML1AuthnAssertionOutbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            List<WSSConstants.Action> actions = new ArrayList<WSSConstants.Action>();
            actions.add(WSSConstants.SAML_TOKEN_SIGNED);
            securityProperties.setActions(actions);
            SAMLCallbackHandlerImpl callbackHandler = new SAMLCallbackHandlerImpl();
            callbackHandler.setStatement(SAMLCallbackHandlerImpl.Statement.AUTHN);
            callbackHandler.setConfirmationMethod(SAML1Constants.CONF_HOLDER_KEY);
            callbackHandler.setIssuer("www.example.com");
            securityProperties.setSamlCallbackHandler(callbackHandler);
            KeyStore keyStore = KeyStore.getInstance("jks");
            keyStore.load(this.getClass().getClassLoader().getResourceAsStream("transmitter.jks"), "default".toCharArray());
            Merlin crypto = new Merlin();
            crypto.setKeyStore(keyStore);
            CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
            cryptoType.setAlias("transmitter");
            callbackHandler.setCerts(crypto.getX509Certificates(cryptoType));
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
            Assert.assertEquals(nodeList.getLength(), 2);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_saml_Assertion.getLocalPart());
            Assert.assertEquals(nodeList.item(1).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

            nodeList = document.getElementsByTagNameNS("urn:oasis:names:tc:SAML:1.0:assertion", "AuthenticationStatement");
            Assert.assertEquals(nodeList.getLength(), 1);

            nodeList = document.getElementsByTagNameNS("urn:oasis:names:tc:SAML:1.0:assertion", "ConfirmationMethod");
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getTextContent().trim(), "urn:oasis:names:tc:SAML:1.0:cm:holder-of-key");
        }

        //done signature; now test sig-verification:
        {
            String action = WSHandlerConstants.SIGNATURE + " " + WSHandlerConstants.SAML_TOKEN_SIGNED;
            Properties properties = new Properties();
            doInboundSecurityWithWSS4J_1(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action, properties, false);
        }
    }

    @Test
    public void testSAML1AuthnAssertionInbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
            callbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHN);
            callbackHandler.setConfirmationMethod(SAML1Constants.CONF_HOLDER_KEY);
            callbackHandler.setIssuer("www.example.com");

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.SAML_TOKEN_SIGNED;
            Properties properties = new Properties();
            properties.put(WSHandlerConstants.SAML_CALLBACK_REF, callbackHandler);
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 2);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_saml_Assertion.getLocalPart());
            Assert.assertEquals(nodeList.item(1).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

            nodeList = securedDocument.getElementsByTagNameNS("urn:oasis:names:tc:SAML:1.0:assertion", "AuthenticationStatement");
            Assert.assertEquals(nodeList.getLength(), 1);

            nodeList = securedDocument.getElementsByTagNameNS("urn:oasis:names:tc:SAML:1.0:assertion", "ConfirmationMethod");
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getTextContent().trim(), "urn:oasis:names:tc:SAML:1.0:cm:holder-of-key");

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

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 2);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_saml_Assertion.getLocalPart());
            Assert.assertEquals(nodeList.item(1).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());
        }
    }

    @Test
    public void testSAML1AuthnAssertionIssuerSerialOutbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            List<WSSConstants.Action> actions = new ArrayList<WSSConstants.Action>();
            actions.add(WSSConstants.SAML_TOKEN_SIGNED);
            securityProperties.setActions(actions);
            SAMLCallbackHandlerImpl callbackHandler = new SAMLCallbackHandlerImpl();
            callbackHandler.setStatement(SAMLCallbackHandlerImpl.Statement.AUTHN);
            callbackHandler.setConfirmationMethod(SAML1Constants.CONF_HOLDER_KEY);
            callbackHandler.setCertIdentifier(KeyInfoBean.CERT_IDENTIFIER.X509_ISSUER_SERIAL);
            callbackHandler.setIssuer("www.example.com");
            securityProperties.setSamlCallbackHandler(callbackHandler);
            KeyStore keyStore = KeyStore.getInstance("jks");
            keyStore.load(this.getClass().getClassLoader().getResourceAsStream("transmitter.jks"), "default".toCharArray());
            Merlin crypto = new Merlin();
            crypto.setKeyStore(keyStore);
            CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
            cryptoType.setAlias("transmitter");
            callbackHandler.setCerts(crypto.getX509Certificates(cryptoType));
            securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setSignatureUser("transmitter");
            securityProperties.setSignatureKeyIdentifier(WSSecurityTokenConstants.KeyIdentifier_EmbeddedKeyIdentifierRef);
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, StandardCharsets.UTF_8.name(), new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 2);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_saml_Assertion.getLocalPart());
            Assert.assertEquals(nodeList.item(1).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

            nodeList = document.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "X509IssuerSerial");
            Assert.assertEquals(nodeList.getLength(), 1);

            nodeList = document.getElementsByTagNameNS("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd", "KeyIdentifier");
            Assert.assertEquals(nodeList.getLength(), 1);

            nodeList = document.getElementsByTagNameNS("urn:oasis:names:tc:SAML:1.0:assertion", "AuthenticationStatement");
            Assert.assertEquals(nodeList.getLength(), 1);

            nodeList = document.getElementsByTagNameNS("urn:oasis:names:tc:SAML:1.0:assertion", "ConfirmationMethod");
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getTextContent().trim(), "urn:oasis:names:tc:SAML:1.0:cm:holder-of-key");
        }

        //done signature; now test sig-verification:
        {
            String action = WSHandlerConstants.SIGNATURE + " " + WSHandlerConstants.SAML_TOKEN_SIGNED;
            Properties properties = new Properties();
            doInboundSecurityWithWSS4J_1(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action, properties, false);
        }
    }

    @Test
    public void testSAML1AuthnAssertionIssuerSerialInbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
            callbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHN);
            callbackHandler.setConfirmationMethod(SAML1Constants.CONF_HOLDER_KEY);
            callbackHandler.setCertIdentifier(KeyInfoBean.CERT_IDENTIFIER.X509_ISSUER_SERIAL);
            callbackHandler.setIssuer("www.example.com");

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.SAML_TOKEN_SIGNED;
            Properties properties = new Properties();
            properties.put(WSHandlerConstants.SAML_CALLBACK_REF, callbackHandler);
            properties.put(WSHandlerConstants.SIG_KEY_ID, "DirectReference");
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 2);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_saml_Assertion.getLocalPart());
            Assert.assertEquals(nodeList.item(1).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

            nodeList = securedDocument.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "X509IssuerSerial");
            Assert.assertEquals(nodeList.getLength(), 1);

            nodeList = securedDocument.getElementsByTagNameNS("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd", "KeyIdentifier");
            Assert.assertEquals(nodeList.getLength(), 1);

            nodeList = securedDocument.getElementsByTagNameNS("urn:oasis:names:tc:SAML:1.0:assertion", "AuthenticationStatement");
            Assert.assertEquals(nodeList.getLength(), 1);

            nodeList = securedDocument.getElementsByTagNameNS("urn:oasis:names:tc:SAML:1.0:assertion", "ConfirmationMethod");
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getTextContent().trim(), "urn:oasis:names:tc:SAML:1.0:cm:holder-of-key");

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

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 2);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_saml_Assertion.getLocalPart());
            Assert.assertEquals(nodeList.item(1).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());
        }
    }

    @Test
    public void testSAML1AuthnAssertionKeyValueOutbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            List<WSSConstants.Action> actions = new ArrayList<WSSConstants.Action>();
            actions.add(WSSConstants.SAML_TOKEN_SIGNED);
            securityProperties.setActions(actions);
            SAMLCallbackHandlerImpl callbackHandler = new SAMLCallbackHandlerImpl();
            callbackHandler.setStatement(SAMLCallbackHandlerImpl.Statement.AUTHN);
            callbackHandler.setConfirmationMethod(SAML1Constants.CONF_HOLDER_KEY);
            callbackHandler.setCertIdentifier(KeyInfoBean.CERT_IDENTIFIER.KEY_VALUE);
            callbackHandler.setIssuer("www.example.com");
            securityProperties.setSamlCallbackHandler(callbackHandler);
            KeyStore keyStore = KeyStore.getInstance("jks");
            keyStore.load(this.getClass().getClassLoader().getResourceAsStream("transmitter.jks"), "default".toCharArray());
            Merlin crypto = new Merlin();
            crypto.setKeyStore(keyStore);
            CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
            cryptoType.setAlias("transmitter");
            callbackHandler.setCerts(crypto.getX509Certificates(cryptoType));
            securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setSignatureUser("transmitter");
            securityProperties.setSignatureKeyIdentifier(WSSecurityTokenConstants.KeyIdentifier_EmbeddedKeyIdentifierRef);
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, StandardCharsets.UTF_8.name(), new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 2);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_saml_Assertion.getLocalPart());
            Assert.assertEquals(nodeList.item(1).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

            nodeList = document.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "KeyValue");
            Assert.assertEquals(nodeList.getLength(), 1);

            nodeList = document.getElementsByTagNameNS("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd", "KeyIdentifier");
            Assert.assertEquals(nodeList.getLength(), 1);

            nodeList = document.getElementsByTagNameNS("urn:oasis:names:tc:SAML:1.0:assertion", "AuthenticationStatement");
            Assert.assertEquals(nodeList.getLength(), 1);

            nodeList = document.getElementsByTagNameNS("urn:oasis:names:tc:SAML:1.0:assertion", "ConfirmationMethod");
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getTextContent().trim(), "urn:oasis:names:tc:SAML:1.0:cm:holder-of-key");
        }

        //done signature; now test sig-verification:
        {
            String action = WSHandlerConstants.SIGNATURE + " " + WSHandlerConstants.SAML_TOKEN_SIGNED;
            Properties properties = new Properties();
            doInboundSecurityWithWSS4J_1(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action, properties, false);
        }
    }

    @Test
    public void testSAML1AuthnAssertionKeyValueInbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
            callbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHN);
            callbackHandler.setConfirmationMethod(SAML1Constants.CONF_HOLDER_KEY);
            callbackHandler.setCertIdentifier(KeyInfoBean.CERT_IDENTIFIER.KEY_VALUE);
            callbackHandler.setIssuer("www.example.com");

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.SAML_TOKEN_SIGNED;
            Properties properties = new Properties();
            properties.put(WSHandlerConstants.SAML_CALLBACK_REF, callbackHandler);
            properties.put(WSHandlerConstants.SIG_KEY_ID, "DirectReference");
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 2);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_saml_Assertion.getLocalPart());
            Assert.assertEquals(nodeList.item(1).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

            nodeList = securedDocument.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "KeyValue");
            Assert.assertEquals(nodeList.getLength(), 1);

            nodeList = securedDocument.getElementsByTagNameNS("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd", "KeyIdentifier");
            Assert.assertEquals(nodeList.getLength(), 1);

            nodeList = securedDocument.getElementsByTagNameNS("urn:oasis:names:tc:SAML:1.0:assertion", "AuthenticationStatement");
            Assert.assertEquals(nodeList.getLength(), 1);

            nodeList = securedDocument.getElementsByTagNameNS("urn:oasis:names:tc:SAML:1.0:assertion", "ConfirmationMethod");
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getTextContent().trim(), "urn:oasis:names:tc:SAML:1.0:cm:holder-of-key");

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

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 2);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_saml_Assertion.getLocalPart());
            Assert.assertEquals(nodeList.item(1).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());
        }
    }

    @Test
    public void testSAML1AttrAssertionOutbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            List<WSSConstants.Action> actions = new ArrayList<WSSConstants.Action>();
            actions.add(WSSConstants.SAML_TOKEN_SIGNED);
            securityProperties.setActions(actions);
            SAMLCallbackHandlerImpl callbackHandler = new SAMLCallbackHandlerImpl();
            callbackHandler.setStatement(SAMLCallbackHandlerImpl.Statement.ATTR);
            callbackHandler.setConfirmationMethod(SAML1Constants.CONF_HOLDER_KEY);
            callbackHandler.setIssuer("www.example.com");
            securityProperties.setSamlCallbackHandler(callbackHandler);
            KeyStore keyStore = KeyStore.getInstance("jks");
            keyStore.load(this.getClass().getClassLoader().getResourceAsStream("receiver.jks"), "default".toCharArray());
            Merlin crypto = new Merlin();
            crypto.setKeyStore(keyStore);
            CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
            cryptoType.setAlias("receiver");
            callbackHandler.setCerts(crypto.getX509Certificates(cryptoType));
            securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setSignatureUser("transmitter");
            securityProperties.setSignatureAlgorithm("http://www.w3.org/2001/04/xmldsig-more#hmac-sha256");
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, StandardCharsets.UTF_8.name(), new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 2);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_saml_Assertion.getLocalPart());
            Assert.assertEquals(nodeList.item(1).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

            nodeList = document.getElementsByTagNameNS("urn:oasis:names:tc:SAML:1.0:assertion", "AttributeStatement");
            Assert.assertEquals(nodeList.getLength(), 1);

            nodeList = document.getElementsByTagNameNS("urn:oasis:names:tc:SAML:1.0:assertion", "ConfirmationMethod");
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getTextContent().trim(), "urn:oasis:names:tc:SAML:1.0:cm:holder-of-key");
        }

        //done signature; now test sig-verification:
        {
            String action = WSHandlerConstants.SIGNATURE + " " + WSHandlerConstants.SAML_TOKEN_SIGNED;
            Properties properties = new Properties();
            doInboundSecurityWithWSS4J_1(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action, properties, false);
        }
    }

    // TODO Not working with OpenSAML 3.0 upgrade
    @Test
    @org.junit.Ignore
    public void testSAML1AttrAssertionInbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
            callbackHandler.setStatement(SAML1CallbackHandler.Statement.ATTR);
            callbackHandler.setConfirmationMethod(SAML1Constants.CONF_HOLDER_KEY);
            callbackHandler.setIssuer("www.example.com");

            SAMLCallback samlCallback = new SAMLCallback();
            SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
            SamlAssertionWrapper samlAssertion = new SamlAssertionWrapper(samlCallback);

            Crypto crypto = CryptoFactory.getInstance("saml/saml-signed.properties");
            samlAssertion.signAssertion("transmitter", "default", crypto, false);

            WSSecSAMLToken wsSign = new WSSecSAMLToken();

            Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
            WSSecHeader secHeader = new WSSecHeader(doc);
            secHeader.insertSecurityHeader();

            Document securedDocument = wsSign.build(doc, samlAssertion, secHeader);

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_saml_Assertion.getLocalPart());

            nodeList = securedDocument.getElementsByTagNameNS("urn:oasis:names:tc:SAML:1.0:assertion", "AttributeStatement");
            Assert.assertEquals(nodeList.getLength(), 1);

            nodeList = securedDocument.getElementsByTagNameNS("urn:oasis:names:tc:SAML:1.0:assertion", "ConfirmationMethod");
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getTextContent().trim(), "urn:oasis:names:tc:SAML:1.0:cm:holder-of-key");

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        //done signature; now test sig-verification:
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setValidateSamlSubjectConfirmation(false);
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_saml_Assertion.getLocalPart());
        }
    }

    @Test
    public void testSAMLAssertionHOKTransportSecurityInbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
            callbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHN);
            callbackHandler.setConfirmationMethod(SAML1Constants.CONF_HOLDER_KEY);
            callbackHandler.setIssuer("www.example.com");
            //callbackHandler.setResource("http://resource.org");

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.SAML_TOKEN_SIGNED;
            Properties properties = new Properties();
            properties.put(WSHandlerConstants.SAML_CALLBACK_REF, callbackHandler);
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 2);

            Element messageSig = (Element)nodeList.item(1);
            messageSig.getParentNode().removeChild(messageSig);

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        //done signature; now test sig-verification:
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setSamlCallbackHandler(new SAMLCallbackHandlerImpl());
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);

            HttpsTokenSecurityEvent httpsTokenSecurityEvent = new HttpsTokenSecurityEvent();
            httpsTokenSecurityEvent.setAuthenticationType(HttpsTokenSecurityEvent.AuthenticationType.HttpsClientCertificateAuthentication);
            CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
            cryptoType.setAlias("transmitter");
            HttpsSecurityToken httpsSecurityToken = new HttpsSecurityTokenImpl(
                    securityProperties.getSignatureVerificationCrypto().getX509Certificates(cryptoType)[0]);
            httpsTokenSecurityEvent.setSecurityToken(httpsSecurityToken);

            List<SecurityEvent> requestSecurityEvents = new ArrayList<SecurityEvent>();
            requestSecurityEvents.add(httpsTokenSecurityEvent);

            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(
                    xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())),
                    requestSecurityEvents);

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
        }
    }

    @Test
    public void testSAML2AuthnOutbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            List<WSSConstants.Action> actions = new ArrayList<WSSConstants.Action>();
            actions.add(WSSConstants.SAML_TOKEN_SIGNED);
            securityProperties.setActions(actions);
            SAMLCallbackHandlerImpl callbackHandler = new SAMLCallbackHandlerImpl();
            callbackHandler.setSamlVersion(Version.SAML_20);
            callbackHandler.setStatement(SAMLCallbackHandlerImpl.Statement.AUTHN);
            callbackHandler.setConfirmationMethod(SAML2Constants.CONF_HOLDER_KEY);
            callbackHandler.setIssuer("www.example.com");
            securityProperties.setSamlCallbackHandler(callbackHandler);
            KeyStore keyStore = KeyStore.getInstance("jks");
            keyStore.load(this.getClass().getClassLoader().getResourceAsStream("transmitter.jks"), "default".toCharArray());
            Merlin crypto = new Merlin();
            crypto.setKeyStore(keyStore);
            CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
            cryptoType.setAlias("transmitter");
            callbackHandler.setCerts(crypto.getX509Certificates(cryptoType));
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
            Assert.assertEquals(nodeList.getLength(), 2);
        }

        //done signature; now test sig-verification:
        {
            String action = WSHandlerConstants.SIGNATURE + " " + WSHandlerConstants.SAML_TOKEN_SIGNED;
            Properties properties = new Properties();
            doInboundSecurityWithWSS4J_1(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action, properties, false);
        }
    }

    @Test
    public void testSAML2AuthnAssertionInbound() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
            callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
            callbackHandler.setConfirmationMethod(SAML2Constants.CONF_HOLDER_KEY);
            callbackHandler.setIssuer("www.example.com");

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.SAML_TOKEN_SIGNED;
            Properties properties = new Properties();
            properties.put(WSHandlerConstants.SAML_CALLBACK_REF, callbackHandler);
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 2);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_saml2_Assertion.getLocalPart());
            Assert.assertEquals(nodeList.item(1).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

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

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 2);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_saml2_Assertion.getLocalPart());
            Assert.assertEquals(nodeList.item(1).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());
        }
    }

    @Test
    public void testSAML2AuthnAssertionIssuerSerialOutbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            List<WSSConstants.Action> actions = new ArrayList<WSSConstants.Action>();
            actions.add(WSSConstants.SAML_TOKEN_SIGNED);
            securityProperties.setActions(actions);
            SAMLCallbackHandlerImpl callbackHandler = new SAMLCallbackHandlerImpl();
            callbackHandler.setSamlVersion(Version.SAML_20);
            callbackHandler.setStatement(SAMLCallbackHandlerImpl.Statement.AUTHN);
            callbackHandler.setConfirmationMethod(SAML2Constants.CONF_HOLDER_KEY);
            callbackHandler.setCertIdentifier(KeyInfoBean.CERT_IDENTIFIER.X509_ISSUER_SERIAL);
            callbackHandler.setIssuer("www.example.com");
            securityProperties.setSamlCallbackHandler(callbackHandler);
            KeyStore keyStore = KeyStore.getInstance("jks");
            keyStore.load(this.getClass().getClassLoader().getResourceAsStream("transmitter.jks"), "default".toCharArray());
            Merlin crypto = new Merlin();
            crypto.setKeyStore(keyStore);
            CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
            cryptoType.setAlias("transmitter");
            callbackHandler.setCerts(crypto.getX509Certificates(cryptoType));
            securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setSignatureUser("transmitter");
            securityProperties.setSignatureKeyIdentifier(WSSecurityTokenConstants.KeyIdentifier_EmbeddedKeyIdentifierRef);
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, StandardCharsets.UTF_8.name(), new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 2);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_saml_Assertion.getLocalPart());
            Assert.assertEquals(nodeList.item(1).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

            nodeList = document.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "X509IssuerSerial");
            Assert.assertEquals(nodeList.getLength(), 1);

            nodeList = document.getElementsByTagNameNS("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd", "KeyIdentifier");
            Assert.assertEquals(nodeList.getLength(), 1);

            nodeList = document.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion", "AuthnStatement");
            Assert.assertEquals(nodeList.getLength(), 1);

            nodeList = document.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion", "SubjectConfirmation");
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(((Element) nodeList.item(0)).getAttributeNS(null, "Method"), "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key");
        }

        //done signature; now test sig-verification:
        {
            String action = WSHandlerConstants.SIGNATURE + " " + WSHandlerConstants.SAML_TOKEN_SIGNED;
            Properties properties = new Properties();
            doInboundSecurityWithWSS4J_1(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action, properties, false);
        }
    }

    @Test
    public void testSAML2AuthnAssertionIssuerSerialInbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
            callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
            callbackHandler.setConfirmationMethod(SAML2Constants.CONF_HOLDER_KEY);
            callbackHandler.setCertIdentifier(KeyInfoBean.CERT_IDENTIFIER.X509_ISSUER_SERIAL);
            callbackHandler.setIssuer("www.example.com");

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.SAML_TOKEN_SIGNED;
            Properties properties = new Properties();
            properties.put(WSHandlerConstants.SAML_CALLBACK_REF, callbackHandler);
            properties.put(WSHandlerConstants.SIG_KEY_ID, "DirectReference");
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 2);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_saml_Assertion.getLocalPart());
            Assert.assertEquals(nodeList.item(1).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

            nodeList = securedDocument.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "X509IssuerSerial");
            Assert.assertEquals(nodeList.getLength(), 1);

            nodeList = securedDocument.getElementsByTagNameNS("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd", "KeyIdentifier");
            Assert.assertEquals(nodeList.getLength(), 1);

            nodeList = securedDocument.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion", "AuthnStatement");
            Assert.assertEquals(nodeList.getLength(), 1);

            nodeList = securedDocument.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion", "SubjectConfirmation");
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(((Element) nodeList.item(0)).getAttributeNS(null, "Method"), "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key");

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

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 2);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_saml_Assertion.getLocalPart());
            Assert.assertEquals(nodeList.item(1).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());
        }
    }

    @Test
    public void testSAML2AuthnAssertionKeyValueOutbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            List<WSSConstants.Action> actions = new ArrayList<WSSConstants.Action>();
            actions.add(WSSConstants.SAML_TOKEN_SIGNED);
            securityProperties.setActions(actions);
            SAMLCallbackHandlerImpl callbackHandler = new SAMLCallbackHandlerImpl();
            callbackHandler.setSamlVersion(Version.SAML_20);
            callbackHandler.setStatement(SAMLCallbackHandlerImpl.Statement.AUTHN);
            callbackHandler.setConfirmationMethod(SAML2Constants.CONF_HOLDER_KEY);
            callbackHandler.setCertIdentifier(KeyInfoBean.CERT_IDENTIFIER.KEY_VALUE);
            callbackHandler.setIssuer("www.example.com");
            securityProperties.setSamlCallbackHandler(callbackHandler);
            KeyStore keyStore = KeyStore.getInstance("jks");
            keyStore.load(this.getClass().getClassLoader().getResourceAsStream("transmitter.jks"), "default".toCharArray());
            Merlin crypto = new Merlin();
            crypto.setKeyStore(keyStore);
            CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
            cryptoType.setAlias("transmitter");
            callbackHandler.setCerts(crypto.getX509Certificates(cryptoType));
            securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setSignatureUser("transmitter");
            securityProperties.setSignatureKeyIdentifier(WSSecurityTokenConstants.KeyIdentifier_EmbeddedKeyIdentifierRef);
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, StandardCharsets.UTF_8.name(), new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 2);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_saml_Assertion.getLocalPart());
            Assert.assertEquals(nodeList.item(1).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

            nodeList = document.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "KeyValue");
            Assert.assertEquals(nodeList.getLength(), 1);

            nodeList = document.getElementsByTagNameNS("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd", "KeyIdentifier");
            Assert.assertEquals(nodeList.getLength(), 1);

            nodeList = document.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion", "AuthnStatement");
            Assert.assertEquals(nodeList.getLength(), 1);

            nodeList = document.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion", "SubjectConfirmation");
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(((Element) nodeList.item(0)).getAttributeNS(null, "Method"), "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key");
        }

        //done signature; now test sig-verification:
        {
            String action = WSHandlerConstants.SIGNATURE + " " + WSHandlerConstants.SAML_TOKEN_SIGNED;
            Properties properties = new Properties();
            doInboundSecurityWithWSS4J_1(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action, properties, false);
        }
    }

    @Test
    public void testSAML2AuthnAssertionKeyValueInbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
            callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
            callbackHandler.setConfirmationMethod(SAML2Constants.CONF_HOLDER_KEY);
            callbackHandler.setCertIdentifier(KeyInfoBean.CERT_IDENTIFIER.KEY_VALUE);
            callbackHandler.setIssuer("www.example.com");

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.SAML_TOKEN_SIGNED;
            Properties properties = new Properties();
            properties.put(WSHandlerConstants.SAML_CALLBACK_REF, callbackHandler);
            properties.put(WSHandlerConstants.SIG_KEY_ID, "DirectReference");
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 2);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_saml_Assertion.getLocalPart());
            Assert.assertEquals(nodeList.item(1).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

            nodeList = securedDocument.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "KeyValue");
            Assert.assertEquals(nodeList.getLength(), 1);

            nodeList = securedDocument.getElementsByTagNameNS("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd", "KeyIdentifier");
            Assert.assertEquals(nodeList.getLength(), 1);

            nodeList = securedDocument.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion", "AuthnStatement");
            Assert.assertEquals(nodeList.getLength(), 1);

            nodeList = securedDocument.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion", "SubjectConfirmation");
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(((Element) nodeList.item(0)).getAttributeNS(null, "Method"), "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key");

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

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 2);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_saml_Assertion.getLocalPart());
            Assert.assertEquals(nodeList.item(1).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());
        }
    }

    @Test
    public void testSAML2AttrAssertionOutbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            List<WSSConstants.Action> actions = new ArrayList<WSSConstants.Action>();
            actions.add(WSSConstants.SAML_TOKEN_SIGNED);
            securityProperties.setActions(actions);
            SAMLCallbackHandlerImpl callbackHandler = new SAMLCallbackHandlerImpl();
            callbackHandler.setSamlVersion(Version.SAML_20);
            callbackHandler.setStatement(SAMLCallbackHandlerImpl.Statement.ATTR);
            callbackHandler.setConfirmationMethod(SAML2Constants.CONF_HOLDER_KEY);
            callbackHandler.setIssuer("www.example.com");
            securityProperties.setSamlCallbackHandler(callbackHandler);
            KeyStore keyStore = KeyStore.getInstance("jks");
            keyStore.load(this.getClass().getClassLoader().getResourceAsStream("transmitter.jks"), "default".toCharArray());
            Merlin crypto = new Merlin();
            crypto.setKeyStore(keyStore);
            CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
            cryptoType.setAlias("receiver");
            callbackHandler.setCerts(crypto.getX509Certificates(cryptoType));
            securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setSignatureUser("receiver");
            securityProperties.setSignatureAlgorithm("http://www.w3.org/2001/04/xmldsig-more#hmac-sha256");
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, StandardCharsets.UTF_8.name(), new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 2);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_saml_Assertion.getLocalPart());
            Assert.assertEquals(nodeList.item(1).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

            nodeList = document.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion", "AttributeStatement");
            Assert.assertEquals(nodeList.getLength(), 1);

            nodeList = document.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion", "SubjectConfirmation");
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(((Element)nodeList.item(0)).getAttributeNS(null, "Method"), "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key");
        }

        //done signature; now test sig-verification:
        {
            String action = WSHandlerConstants.SIGNATURE + " " + WSHandlerConstants.SAML_TOKEN_SIGNED;
            Properties properties = new Properties();
            doInboundSecurityWithWSS4J_1(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action, properties, false);
        }
    }

    // TODO Not working with OpenSAML 3.0 upgrade
    @Test
    @org.junit.Ignore
    public void testSAML2AttrAssertionInbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
            callbackHandler.setStatement(SAML2CallbackHandler.Statement.ATTR);
            callbackHandler.setConfirmationMethod(SAML2Constants.CONF_HOLDER_KEY);
            callbackHandler.setIssuer("www.example.com");

            SAMLCallback samlCallback = new SAMLCallback();
            SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
            SamlAssertionWrapper samlAssertion = new SamlAssertionWrapper(samlCallback);

            Crypto crypto = CryptoFactory.getInstance("saml/saml-signed.properties");
            samlAssertion.signAssertion("transmitter", "default", crypto, false);

            WSSecSAMLToken wsSign = new WSSecSAMLToken();

            Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
            WSSecHeader secHeader = new WSSecHeader(doc);
            secHeader.insertSecurityHeader();

            Document securedDocument = wsSign.build(doc, samlAssertion, secHeader);

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_saml_Assertion.getLocalPart());

            nodeList = securedDocument.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion", "AttributeStatement");
            Assert.assertEquals(nodeList.getLength(), 1);

            nodeList = securedDocument.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion", "SubjectConfirmation");
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(((Element) nodeList.item(0)).getAttributeNS(null, "Method"), "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key");

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        //done signature; now test sig-verification:
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.setValidateSamlSubjectConfirmation(false);
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_saml_Assertion.getLocalPart());
        }
    }

}
