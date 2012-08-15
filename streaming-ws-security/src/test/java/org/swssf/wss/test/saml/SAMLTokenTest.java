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
package org.swssf.wss.test.saml;

import org.apache.ws.security.handler.WSHandlerConstants;
import org.apache.xml.security.stax.securityEvent.SecurityEvent;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.AttributeValue;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.xml.XMLObjectBuilder;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.schema.XSAny;
import org.swssf.wss.WSSec;
import org.swssf.wss.ext.InboundWSSec;
import org.swssf.wss.ext.OutboundWSSec;
import org.swssf.wss.ext.WSSConstants;
import org.swssf.wss.ext.WSSSecurityProperties;
import org.swssf.wss.impl.saml.builder.SAML1Constants;
import org.swssf.wss.test.AbstractTestBase;
import org.swssf.wss.test.CallbackHandlerImpl;
import org.swssf.wss.test.utils.StAX2DOM;
import org.swssf.wss.test.utils.XmlReaderToWriter;
import org.testng.Assert;
import org.testng.annotations.Test;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.XMLStreamWriter;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Properties;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class SAMLTokenTest extends AbstractTestBase {

    @Test
    public void testSAML1AuthnAssertionOutbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.SAML_TOKEN_UNSIGNED};
            securityProperties.setOutAction(actions);
            CallbackHandlerImpl callbackHandler = new CallbackHandlerImpl();
            callbackHandler.setStatement(CallbackHandlerImpl.Statement.AUTHN);
            callbackHandler.setIssuer("www.example.com");
            callbackHandler.setSignAssertion(false);
            securityProperties.setCallbackHandler(callbackHandler);

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, "UTF-8", new ArrayList<SecurityEvent>());
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

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.SAML_TOKEN_UNSIGNED;
            Properties properties = new Properties();
            properties.setProperty(WSHandlerConstants.SAML_PROP_FILE, "saml/saml-unsigned.properties");
            properties.put(WSHandlerConstants.SAML_CALLBACK_REF, callbackHandler);
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 0);

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        //done signature; now test sig-verification:
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 0);
        }
    }

    @Test
    public void testSAML1AttrAssertionOutbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.SAML_TOKEN_UNSIGNED};
            securityProperties.setOutAction(actions);
            CallbackHandlerImpl callbackHandler = new CallbackHandlerImpl();
            callbackHandler.setStatement(CallbackHandlerImpl.Statement.ATTR);
            callbackHandler.setIssuer("www.example.com");
            callbackHandler.setSignAssertion(false);
            securityProperties.setCallbackHandler(callbackHandler);

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, "UTF-8", new ArrayList<SecurityEvent>());
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

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.SAML_TOKEN_UNSIGNED;
            Properties properties = new Properties();
            properties.setProperty(WSHandlerConstants.SAML_PROP_FILE, "saml/saml-unsigned.properties");
            properties.put(WSHandlerConstants.SAML_CALLBACK_REF, callbackHandler);
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 0);

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        //done signature; now test sig-verification:
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 0);
        }
    }

    @Test
    public void testSAML1AuthzAssertionOutbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.SAML_TOKEN_UNSIGNED};
            securityProperties.setOutAction(actions);
            CallbackHandlerImpl callbackHandler = new CallbackHandlerImpl();
            callbackHandler.setStatement(CallbackHandlerImpl.Statement.AUTHZ);
            callbackHandler.setIssuer("www.example.com");
            callbackHandler.setSignAssertion(false);
            callbackHandler.setResource("http://resource.org");
            securityProperties.setCallbackHandler(callbackHandler);

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, "UTF-8", new ArrayList<SecurityEvent>());
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

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.SAML_TOKEN_UNSIGNED;
            Properties properties = new Properties();
            properties.setProperty(WSHandlerConstants.SAML_PROP_FILE, "saml/saml-unsigned.properties");
            properties.put(WSHandlerConstants.SAML_CALLBACK_REF, callbackHandler);
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 0);

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        //done signature; now test sig-verification:
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 0);
        }
    }

    @Test
    public void testSAML2AuthnAssertionOutbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.SAML_TOKEN_UNSIGNED};
            securityProperties.setOutAction(actions);
            CallbackHandlerImpl callbackHandler = new CallbackHandlerImpl();
            callbackHandler.setSamlVersion(SAMLVersion.VERSION_20);
            callbackHandler.setStatement(CallbackHandlerImpl.Statement.AUTHN);
            callbackHandler.setIssuer("www.example.com");
            callbackHandler.setSignAssertion(false);
            securityProperties.setCallbackHandler(callbackHandler);

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, "UTF-8", new ArrayList<SecurityEvent>());
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

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.SAML_TOKEN_UNSIGNED;
            Properties properties = new Properties();
            properties.setProperty(WSHandlerConstants.SAML_PROP_FILE, "saml/saml-unsigned.properties");
            properties.put(WSHandlerConstants.SAML_CALLBACK_REF, callbackHandler);
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 0);

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        //done signature; now test sig-verification:
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 0);
        }
    }

    @Test
    public void testSAML2AttrAssertionOutbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.SAML_TOKEN_UNSIGNED};
            securityProperties.setOutAction(actions);
            CallbackHandlerImpl callbackHandler = new CallbackHandlerImpl();
            callbackHandler.setSamlVersion(SAMLVersion.VERSION_20);
            callbackHandler.setStatement(CallbackHandlerImpl.Statement.ATTR);
            callbackHandler.setIssuer("www.example.com");
            callbackHandler.setSignAssertion(false);
            securityProperties.setCallbackHandler(callbackHandler);

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, "UTF-8", new ArrayList<SecurityEvent>());
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

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.SAML_TOKEN_UNSIGNED;
            Properties properties = new Properties();
            properties.setProperty(WSHandlerConstants.SAML_PROP_FILE, "saml/saml-unsigned.properties");
            properties.put(WSHandlerConstants.SAML_CALLBACK_REF, callbackHandler);
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 0);

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        //done signature; now test sig-verification:
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 0);
        }
    }

    @Test
    public void testSAML2AuthzAssertionOutbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.SAML_TOKEN_UNSIGNED};
            securityProperties.setOutAction(actions);
            CallbackHandlerImpl callbackHandler = new CallbackHandlerImpl();
            callbackHandler.setSamlVersion(SAMLVersion.VERSION_20);
            callbackHandler.setStatement(CallbackHandlerImpl.Statement.AUTHZ);
            callbackHandler.setIssuer("www.example.com");
            callbackHandler.setSignAssertion(false);
            callbackHandler.setResource("http://resource.org");
            securityProperties.setCallbackHandler(callbackHandler);

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, "UTF-8", new ArrayList<SecurityEvent>());
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

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.SAML_TOKEN_UNSIGNED;
            Properties properties = new Properties();
            properties.setProperty(WSHandlerConstants.SAML_PROP_FILE, "saml/saml-unsigned.properties");
            properties.put(WSHandlerConstants.SAML_CALLBACK_REF, callbackHandler);
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 0);

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        //done signature; now test sig-verification:
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 0);
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
            WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.SAML_TOKEN_UNSIGNED};
            securityProperties.setOutAction(actions);
            CallbackHandlerImpl callbackHandler = new CallbackHandlerImpl();
            callbackHandler.setStatement(CallbackHandlerImpl.Statement.AUTHN);
            callbackHandler.setIssuer("www.example.com");
            callbackHandler.setSignAssertion(false);
            callbackHandler.setSubjectNameIDFormat(SAML1Constants.NAMEID_FORMAT_EMAIL_ADDRESS);
            securityProperties.setCallbackHandler(callbackHandler);

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, "UTF-8", new ArrayList<SecurityEvent>());
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
            WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.SAML_TOKEN_UNSIGNED};
            securityProperties.setOutAction(actions);
            CallbackHandlerImpl callbackHandler = new CallbackHandlerImpl();
            callbackHandler.setStatement(CallbackHandlerImpl.Statement.AUTHN);
            callbackHandler.setSamlVersion(SAMLVersion.VERSION_20);
            callbackHandler.setIssuer("www.example.com");
            callbackHandler.setSignAssertion(false);
            callbackHandler.setSubjectNameIDFormat(SAML1Constants.NAMEID_FORMAT_EMAIL_ADDRESS);
            securityProperties.setCallbackHandler(callbackHandler);

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, "UTF-8", new ArrayList<SecurityEvent>());
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
            WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.SAML_TOKEN_UNSIGNED};
            securityProperties.setOutAction(actions);
            CallbackHandlerImpl callbackHandler = new CallbackHandlerImpl();
            callbackHandler.setStatement(CallbackHandlerImpl.Statement.AUTHN);
            callbackHandler.setIssuer("www.example.com");
            callbackHandler.setSignAssertion(false);
            callbackHandler.setSubjectLocality("12.34.56.780", "test-dns");
            securityProperties.setCallbackHandler(callbackHandler);

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, "UTF-8", new ArrayList<SecurityEvent>());
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
            WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.SAML_TOKEN_UNSIGNED};
            securityProperties.setOutAction(actions);
            CallbackHandlerImpl callbackHandler = new CallbackHandlerImpl();
            callbackHandler.setStatement(CallbackHandlerImpl.Statement.AUTHN);
            callbackHandler.setIssuer("www.example.com");
            callbackHandler.setSignAssertion(false);
            callbackHandler.setSamlVersion(SAMLVersion.VERSION_20);
            callbackHandler.setSubjectLocality("12.34.56.780", "test-dns");
            securityProperties.setCallbackHandler(callbackHandler);

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, "UTF-8", new ArrayList<SecurityEvent>());
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
            WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.SAML_TOKEN_UNSIGNED};
            securityProperties.setOutAction(actions);
            CallbackHandlerImpl callbackHandler = new CallbackHandlerImpl();
            callbackHandler.setStatement(CallbackHandlerImpl.Statement.AUTHZ);
            callbackHandler.setIssuer("www.example.com");
            callbackHandler.setResource("http://resource.org");
            callbackHandler.setSignAssertion(false);
            securityProperties.setCallbackHandler(callbackHandler);

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, "UTF-8", new ArrayList<SecurityEvent>());
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
            WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.SAML_TOKEN_UNSIGNED};
            securityProperties.setOutAction(actions);
            CallbackHandlerImpl callbackHandler = new CallbackHandlerImpl();
            callbackHandler.setStatement(CallbackHandlerImpl.Statement.ATTR);
            callbackHandler.setIssuer("www.example.com");
            callbackHandler.setSignAssertion(false);
            callbackHandler.setSamlVersion(SAMLVersion.VERSION_20);

            // Create and add a custom Attribute (conditions Object)
            XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();

            SAMLObjectBuilder<Conditions> conditionsV2Builder =
                    (SAMLObjectBuilder<Conditions>) builderFactory.getBuilder(Conditions.DEFAULT_ELEMENT_NAME);
            Conditions conditions = conditionsV2Builder.buildObject();
            DateTime newNotBefore = new DateTime();
            conditions.setNotBefore(newNotBefore);
            conditions.setNotOnOrAfter(newNotBefore.plusMinutes(5));

            XMLObjectBuilder<XSAny> xsAnyBuilder = builderFactory.getBuilder(XSAny.TYPE_NAME);
            XSAny attributeValue = xsAnyBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME);
            attributeValue.getUnknownXMLObjects().add(conditions);

            callbackHandler.setCustomAttributeValues(Collections.singletonList(attributeValue));

            securityProperties.setCallbackHandler(callbackHandler);

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, "UTF-8", new ArrayList<SecurityEvent>());
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

}
