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
package org.apache.wss4j.stax.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.Security;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.XMLStreamWriter;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;

import org.apache.wss4j.common.ConfigurationConstants;
import org.apache.wss4j.common.bsp.BSPRule;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.ext.WSPasswordCallback;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.handler.WSHandlerConstants;
import org.apache.wss4j.dom.message.WSSecHeader;
import org.apache.wss4j.dom.message.WSSecSignature;
import org.apache.wss4j.stax.ConfigurationConverter;
import org.apache.wss4j.stax.WSSec;
import org.apache.wss4j.stax.ext.InboundWSSec;
import org.apache.wss4j.stax.ext.OutboundWSSec;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.ext.WSSSecurityProperties;
import org.apache.wss4j.stax.securityEvent.OperationSecurityEvent;
import org.apache.wss4j.stax.securityEvent.WSSecurityEventConstants;
import org.apache.wss4j.stax.securityToken.WSSecurityTokenConstants;
import org.apache.wss4j.stax.test.utils.StAX2DOM;
import org.apache.wss4j.stax.test.utils.XmlReaderToWriter;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.ext.SecurePart;
import org.apache.xml.security.stax.securityEvent.SecurityEvent;
import org.apache.xml.security.stax.securityEvent.SignatureValueSecurityEvent;
import org.apache.xml.security.stax.securityEvent.SignedElementSecurityEvent;
import org.testng.Assert;
import org.testng.annotations.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

public class SignatureTest extends AbstractTestBase {

    @Test
    public void testSignatureDefaultConfigurationOutbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.SIGNATURE};
            securityProperties.setOutAction(actions);
            securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setSignatureUser("transmitter");
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, "UTF-8", new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Reference.getNamespaceURI(), WSSConstants.TAG_dsig_Reference.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);

            nodeList = document.getElementsByTagNameNS(WSSConstants.NS_SOAP11, WSSConstants.TAG_soap_Body_LocalName);
            Assert.assertEquals(nodeList.getLength(), 1);
            String idAttrValue = ((Element) nodeList.item(0)).getAttributeNS(WSSConstants.ATT_wsu_Id.getNamespaceURI(), WSSConstants.ATT_wsu_Id.getLocalPart());
            Assert.assertNotNull(idAttrValue);
            Assert.assertTrue(idAttrValue.length() > 0);

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_c14nExcl_InclusiveNamespaces.getNamespaceURI(), WSSConstants.TAG_c14nExcl_InclusiveNamespaces.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 2);
            Assert.assertEquals(((Element) nodeList.item(0)).getAttributeNS(null, WSSConstants.ATT_NULL_PrefixList.getLocalPart()), "env");
            Assert.assertEquals(((Element) nodeList.item(1)).getAttributeNS(null, WSSConstants.ATT_NULL_PrefixList.getLocalPart()), "");
        }
        //done signature; now test sig-verification:
        {
            String action = WSHandlerConstants.SIGNATURE;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @Test
    public void testSignatureDefaultConfigurationInbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.SIGNATURE;
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, new Properties());

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

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
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());
        }
    }
    
    @Test
    public void testSignatureCryptoPropertiesOutbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.SIGNATURE};
            securityProperties.setOutAction(actions);
            Properties properties = 
                CryptoFactory.getProperties("transmitter-crypto.properties", this.getClass().getClassLoader());
            securityProperties.setSignatureCryptoProperties(properties);
            securityProperties.setSignatureUser("transmitter");
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, "UTF-8", new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Reference.getNamespaceURI(), WSSConstants.TAG_dsig_Reference.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);

            nodeList = document.getElementsByTagNameNS(WSSConstants.NS_SOAP11, WSSConstants.TAG_soap_Body_LocalName);
            Assert.assertEquals(nodeList.getLength(), 1);
            String idAttrValue = ((Element) nodeList.item(0)).getAttributeNS(WSSConstants.ATT_wsu_Id.getNamespaceURI(), WSSConstants.ATT_wsu_Id.getLocalPart());
            Assert.assertNotNull(idAttrValue);
            Assert.assertTrue(idAttrValue.length() > 0);

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_c14nExcl_InclusiveNamespaces.getNamespaceURI(), WSSConstants.TAG_c14nExcl_InclusiveNamespaces.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 2);
            Assert.assertEquals(((Element) nodeList.item(0)).getAttributeNS(null, WSSConstants.ATT_NULL_PrefixList.getLocalPart()), "env");
            Assert.assertEquals(((Element) nodeList.item(1)).getAttributeNS(null, WSSConstants.ATT_NULL_PrefixList.getLocalPart()), "");
        }
        //done signature; now test sig-verification:
        {
            String action = WSHandlerConstants.SIGNATURE;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @Test
    public void testSignatureCryptoPropertiesInbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.SIGNATURE;
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, new Properties());

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        //done signature; now test sig-verification:
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            Properties properties = 
                CryptoFactory.getProperties("receiver-crypto.properties", this.getClass().getClassLoader());
            securityProperties.setSignatureVerificationCryptoProperties(properties);
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());
        }
    }

    @Test
    public void testSignaturePartsOutbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.SIGNATURE};
            securityProperties.setOutAction(actions);
            securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setSignatureUser("transmitter");
            securityProperties.addSignaturePart(new SecurePart(new QName("http://www.w3.org/1999/XMLSchema", "complexType"), SecurePart.Modifier.Element));
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, "UTF-8", new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Reference.getNamespaceURI(), WSSConstants.TAG_dsig_Reference.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 25);

            nodeList = document.getElementsByTagNameNS("http://www.w3.org/1999/XMLSchema", "complexType");
            Assert.assertEquals(nodeList.getLength(), 26);
            for (int i = 0; i < nodeList.getLength(); i++) {
                String idAttrValue = ((Element) nodeList.item(i)).getAttributeNS(WSSConstants.ATT_wsu_Id.getNamespaceURI(), WSSConstants.ATT_wsu_Id.getLocalPart());
                if (i == 10) {
                    Assert.assertSame(idAttrValue, "");
                } else {
                    Assert.assertNotSame(idAttrValue, "");
                    Assert.assertTrue(idAttrValue.length() > 0);
                }
            }
        }

        //done signature; now test sig-verification:
        {
            String action = WSHandlerConstants.SIGNATURE;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @Test
    public void testExceptionOnElementToSignNotFound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.SIGNATURE};
            securityProperties.setOutAction(actions);
            securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setSignatureUser("transmitter");
            securityProperties.addSignaturePart(new SecurePart(new QName("http://www.wrongnamespace.org", "complexType"), SecurePart.Modifier.Element));
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, "UTF-8", new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));

            try {
                XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
                xmlStreamWriter.close();
                Assert.fail("Exception expected");
            } catch (XMLStreamException e) {
                org.junit.Assert.assertTrue(e.getCause() instanceof XMLSecurityException);
                org.junit.Assert.assertEquals("Part to sign not found: {http://www.wrongnamespace.org}complexType", e.getCause().getMessage());
            }
        }
    }

    @Test
    public void testSignatureC14NInclusivePartsOutbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.SIGNATURE};
            securityProperties.setOutAction(actions);
            securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setSignatureUser("transmitter");
            securityProperties.addSignaturePart(new SecurePart(new QName("http://www.w3.org/1999/XMLSchema", "complexType"), SecurePart.Modifier.Element));
            securityProperties.setSignatureCanonicalizationAlgorithm("http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments");
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, "UTF-8", new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Reference.getNamespaceURI(), WSSConstants.TAG_dsig_Reference.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 25);

            nodeList = document.getElementsByTagNameNS("http://www.w3.org/1999/XMLSchema", "complexType");
            Assert.assertEquals(nodeList.getLength(), 26);
            for (int i = 0; i < nodeList.getLength(); i++) {
                String idAttrValue = ((Element) nodeList.item(i)).getAttributeNS(WSSConstants.ATT_wsu_Id.getNamespaceURI(), WSSConstants.ATT_wsu_Id.getLocalPart());
                if (i == 10) {
                    Assert.assertSame(idAttrValue, "");
                } else {
                    Assert.assertNotSame(idAttrValue, "");
                    Assert.assertTrue(idAttrValue.length() > 0);
                }
            }
        }

        //done signature; now test sig-verification:
        {
            String action = WSHandlerConstants.SIGNATURE;
            Properties properties = new Properties();
            doInboundSecurityWithWSS4J_1(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action, properties, false);
        }
    }

    @Test
    public void testSignaturePartsInbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.SIGNATURE;
            Properties properties = new Properties();
            properties.setProperty(WSHandlerConstants.SIGNATURE_PARTS, "{Element}{http://www.w3.org/1999/XMLSchema}complexType;");
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

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
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());
        }
    }

    @Test
    public void testSignatureC14NInclusivePartsInbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.SIGNATURE;
            Properties properties = new Properties();
            properties.setProperty(WSHandlerConstants.SIGNATURE_PARTS, "{Element}{http://www.w3.org/1999/XMLSchema}complexType;");
            properties.setProperty("CanonicalizationAlgo", "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments");
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

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
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());
        }
    }

    /**
     * Since WSS4J hardcoded the C14N algo for References, we test against our framework
     *
     * @throws Exception
     */
    @Test
    public void testSignatureC14NInclusivePartsInbound_1() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.SIGNATURE};
            securityProperties.setOutAction(actions);
            securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setSignatureUser("transmitter");
            securityProperties.addSignaturePart(new SecurePart(new QName("http://www.w3.org/1999/XMLSchema", "complexType"), SecurePart.Modifier.Element));
            securityProperties.setSignatureCanonicalizationAlgorithm("http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments");
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, "UTF-8", new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document securedDocument = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = securedDocument.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());
        }

        //done signature; now test sig-verification:
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.addIgnoreBSPRule(BSPRule.R5404);
            securityProperties.addIgnoreBSPRule(BSPRule.R5423);
            securityProperties.addIgnoreBSPRule(BSPRule.R5412);
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());
        }
    }
    
    /**
     * Since WSS4J hardcoded the C14N algo for References, we test against our framework
     *
     * @throws Exception
     */
    @Test
    public void testSignatureC14NInclusivePartsInbound_DisableAllBSPRules() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.SIGNATURE};
            securityProperties.setOutAction(actions);
            securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setSignatureUser("transmitter");
            securityProperties.addSignaturePart(new SecurePart(new QName("http://www.w3.org/1999/XMLSchema", "complexType"), SecurePart.Modifier.Element));
            securityProperties.setSignatureCanonicalizationAlgorithm("http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments");
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, "UTF-8", new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document securedDocument = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = securedDocument.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());
        }

        //done signature; now test sig-verification:
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.setDisableBSPEnforcement(true);
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());
        }
    }

    @Test
    public void testSignatureKeyIdentifierIssuerSerialOutbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.SIGNATURE};
            securityProperties.setOutAction(actions);
            securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setSignatureUser("transmitter");
            securityProperties.setSignatureKeyIdentifier(WSSecurityTokenConstants.KeyIdentifier_IssuerSerial);
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, "UTF-8", new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

            XPathExpression xPathExpression = getXPath("/env:Envelope/env:Header/wsse:Security/dsig:Signature/dsig:KeyInfo/wsse:SecurityTokenReference/dsig:X509Data/dsig:X509IssuerSerial/dsig:X509SerialNumber");
            Node node = (Node) xPathExpression.evaluate(document, XPathConstants.NODE);
            Assert.assertNotNull(node);

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Reference.getNamespaceURI(), WSSConstants.TAG_dsig_Reference.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);

            nodeList = document.getElementsByTagNameNS(WSSConstants.NS_SOAP11, WSSConstants.TAG_soap_Body_LocalName);
            Assert.assertEquals(nodeList.getLength(), 1);
            String idAttrValue = ((Element) nodeList.item(0)).getAttributeNS(WSSConstants.ATT_wsu_Id.getNamespaceURI(), WSSConstants.ATT_wsu_Id.getLocalPart());
            Assert.assertNotNull(idAttrValue);
            Assert.assertTrue(idAttrValue.length() > 0);
        }

        //done signature; now test sig-verification:
        {
            String action = WSHandlerConstants.SIGNATURE;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @Test
    public void testSignatureKeyIdentifierIssuerSerialInbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.SIGNATURE;
            Properties properties = new Properties();
            properties.setProperty(WSHandlerConstants.SIG_KEY_ID, "IssuerSerial");
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            XPathExpression xPathExpression = getXPath("/env:Envelope/env:Header/wsse:Security/dsig:Signature/dsig:KeyInfo/wsse:SecurityTokenReference/dsig:X509Data/dsig:X509IssuerSerial/dsig:X509SerialNumber");
            Node node = (Node) xPathExpression.evaluate(securedDocument, XPathConstants.NODE);
            Assert.assertNotNull(node);

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
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());
        }
    }
    
    @Test
    public void testSignatureKeyIdentifierIssuerSerialIncludeTokenOutbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.SIGNATURE};
            securityProperties.setOutAction(actions);
            securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setSignatureUser("transmitter");
            securityProperties.setSignatureKeyIdentifier(WSSecurityTokenConstants.KeyIdentifier_IssuerSerial);
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            securityProperties.setIncludeSignatureToken(true);

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, "UTF-8", new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

            XPathExpression xPathExpression = getXPath("/env:Envelope/env:Header/wsse:Security/dsig:Signature/dsig:KeyInfo/wsse:SecurityTokenReference/dsig:X509Data/dsig:X509IssuerSerial/dsig:X509SerialNumber");
            Node node = (Node) xPathExpression.evaluate(document, XPathConstants.NODE);
            Assert.assertNotNull(node);

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Reference.getNamespaceURI(), WSSConstants.TAG_dsig_Reference.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);

            nodeList = document.getElementsByTagNameNS(WSSConstants.NS_SOAP11, WSSConstants.TAG_soap_Body_LocalName);
            Assert.assertEquals(nodeList.getLength(), 1);
            String idAttrValue = ((Element) nodeList.item(0)).getAttributeNS(WSSConstants.ATT_wsu_Id.getNamespaceURI(), WSSConstants.ATT_wsu_Id.getLocalPart());
            Assert.assertNotNull(idAttrValue);
            Assert.assertTrue(idAttrValue.length() > 0);
        }

        //done signature; now test sig-verification:
        {
            String action = WSHandlerConstants.SIGNATURE;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @Test
    public void testSignatureKeyIdentifierBinarySecurityTokenDirectReferenceOutbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.SIGNATURE};
            securityProperties.setOutAction(actions);
            securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setSignatureUser("transmitter");
            securityProperties.setSignatureKeyIdentifier(WSSecurityTokenConstants.KeyIdentifier_SecurityTokenDirectReference);
            securityProperties.setCallbackHandler(new org.apache.wss4j.stax.test.CallbackHandlerImpl());

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, "UTF-8", new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

            XPathExpression xPathExpression = getXPath("/env:Envelope/env:Header/wsse:Security/wsse:BinarySecurityToken");
            Node node = (Node) xPathExpression.evaluate(document, XPathConstants.NODE);
            Assert.assertNotNull(node);

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Reference.getNamespaceURI(), WSSConstants.TAG_dsig_Reference.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);

            nodeList = document.getElementsByTagNameNS(WSSConstants.NS_SOAP11, WSSConstants.TAG_soap_Body_LocalName);
            Assert.assertEquals(nodeList.getLength(), 1);
            String idAttrValue = ((Element) nodeList.item(0)).getAttributeNS(WSSConstants.ATT_wsu_Id.getNamespaceURI(), WSSConstants.ATT_wsu_Id.getLocalPart());
            Assert.assertNotNull(idAttrValue);
            Assert.assertTrue(idAttrValue.length() > 0);
        }

        //done signature; now test sig-verification:
        {
            String action = WSHandlerConstants.SIGNATURE;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @Test
    public void testSignatureKeyIdentifierBinarySecurityTokenDirectReferenceInbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.SIGNATURE;
            Properties properties = new Properties();
            properties.setProperty(WSHandlerConstants.SIG_KEY_ID, "DirectReference");
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            XPathExpression xPathExpression = getXPath("/env:Envelope/env:Header/wsse:Security/wsse:BinarySecurityToken");
            Node node = (Node) xPathExpression.evaluate(securedDocument, XPathConstants.NODE);
            Assert.assertNotNull(node);

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
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());
        }
    }

/*  Not spec conform and therefore not supported!:
    @Test
    public void testSignatureKeyIdentifierBinarySecurityTokenEmbedded() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.SIGNATURE};
            securityProperties.setOutAction(actions);
            securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setSignatureUser("transmitter");
            securityProperties.setSignatureKeyIdentifierType(WSSConstants.WSSKeyIdentifierType.BST_EMBEDDED);
            securityProperties.setCallbackHandler(new org.apache.wss4j.stax.test.CallbackHandlerImpl());

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, "UTF-8", new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

            XPathExpression xPathExpression = getXPath("/env:Envelope/env:Header/wsse:Security/dsig:Signature/dsig:KeyInfo/wsse:SecurityTokenReference/wsse:Reference/wsse:BinarySecurityToken");
            Node node = (Node) xPathExpression.evaluate(document, XPathConstants.NODE);
            Assert.assertNotNull(node);

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Reference.getNamespaceURI(), WSSConstants.TAG_dsig_Reference.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);

            nodeList = document.getElementsByTagNameNS(WSSConstants.NS_SOAP11, WSSConstants.TAG_soap_Body_LocalName);
            Assert.assertEquals(nodeList.getLength(), 1);
            String idAttrValue = ((Element) nodeList.item(0)).getAttributeNS(WSSConstants.ATT_wsu_Id.getNamespaceURI(), WSSConstants.ATT_wsu_Id.getLocalPart());
            Assert.assertNotNull(idAttrValue);
            Assert.assertTrue(idAttrValue.length() > 0);
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
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());
        }
    }*/

    @Test
    public void testSignatureKeyIdentifierX509KeyOutbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.SIGNATURE};
            securityProperties.setOutAction(actions);
            securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setSignatureUser("transmitter");
            securityProperties.setSignatureKeyIdentifier(WSSecurityTokenConstants.KeyIdentifier_X509KeyIdentifier);
            securityProperties.setCallbackHandler(new org.apache.wss4j.stax.test.CallbackHandlerImpl());

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, "UTF-8", new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

            XPathExpression xPathExpression = getXPath("/env:Envelope/env:Header/wsse:Security/dsig:Signature/dsig:KeyInfo/wsse:SecurityTokenReference/wsse:KeyIdentifier[@ValueType='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3']");
            Node node = (Node) xPathExpression.evaluate(document, XPathConstants.NODE);
            Assert.assertNotNull(node);

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Reference.getNamespaceURI(), WSSConstants.TAG_dsig_Reference.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);

            nodeList = document.getElementsByTagNameNS(WSSConstants.NS_SOAP11, WSSConstants.TAG_soap_Body_LocalName);
            Assert.assertEquals(nodeList.getLength(), 1);
            String idAttrValue = ((Element) nodeList.item(0)).getAttributeNS(WSSConstants.ATT_wsu_Id.getNamespaceURI(), WSSConstants.ATT_wsu_Id.getLocalPart());
            Assert.assertNotNull(idAttrValue);
            Assert.assertTrue(idAttrValue.length() > 0);
        }

        //done signature; now test sig-verification:
        {
            String action = WSHandlerConstants.SIGNATURE;
            Properties properties = new Properties();
            doInboundSecurityWithWSS4J_1(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action, properties, false);
        }
    }

    @Test
    public void testSignatureKeyIdentifierX509KeyInbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.SIGNATURE;
            Properties properties = new Properties();
            properties.setProperty(WSHandlerConstants.SIG_KEY_ID, "X509KeyIdentifier");
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            XPathExpression xPathExpression = getXPath("/env:Envelope/env:Header/wsse:Security/dsig:Signature/dsig:KeyInfo/wsse:SecurityTokenReference/wsse:KeyIdentifier[@ValueType='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3']");
            Node node = (Node) xPathExpression.evaluate(securedDocument, XPathConstants.NODE);
            Assert.assertNotNull(node);

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
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());
        }
    }

    @Test
    public void testSignatureKeyIdentifierSubjectKeyOutbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.SIGNATURE};
            securityProperties.setOutAction(actions);
            securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setSignatureUser("transmitter");
            securityProperties.setSignatureKeyIdentifier(WSSecurityTokenConstants.KeyIdentifier_SkiKeyIdentifier);
            securityProperties.setCallbackHandler(new org.apache.wss4j.stax.test.CallbackHandlerImpl());

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, "UTF-8", new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

            XPathExpression xPathExpression = getXPath("/env:Envelope/env:Header/wsse:Security/dsig:Signature/dsig:KeyInfo/wsse:SecurityTokenReference/wsse:KeyIdentifier[@ValueType='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509SubjectKeyIdentifier']");
            Node node = (Node) xPathExpression.evaluate(document, XPathConstants.NODE);
            Assert.assertNotNull(node);

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Reference.getNamespaceURI(), WSSConstants.TAG_dsig_Reference.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);

            nodeList = document.getElementsByTagNameNS(WSSConstants.NS_SOAP11, WSSConstants.TAG_soap_Body_LocalName);
            Assert.assertEquals(nodeList.getLength(), 1);
            String idAttrValue = ((Element) nodeList.item(0)).getAttributeNS(WSSConstants.ATT_wsu_Id.getNamespaceURI(), WSSConstants.ATT_wsu_Id.getLocalPart());
            Assert.assertNotNull(idAttrValue);
            Assert.assertTrue(idAttrValue.length() > 0);
        }

        //done signature; now test sig-verification:
        {
            String action = WSHandlerConstants.SIGNATURE;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @Test
    public void testSignatureKeyIdentifierSubjectKeyInbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.SIGNATURE;
            Properties properties = new Properties();
            properties.setProperty(WSHandlerConstants.SIG_KEY_ID, "SKIKeyIdentifier");
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            XPathExpression xPathExpression = getXPath("/env:Envelope/env:Header/wsse:Security/dsig:Signature/dsig:KeyInfo/wsse:SecurityTokenReference/wsse:KeyIdentifier[@ValueType='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509SubjectKeyIdentifier']");
            Node node = (Node) xPathExpression.evaluate(securedDocument, XPathConstants.NODE);
            Assert.assertNotNull(node);

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
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());
        }
    }

    @Test
    public void testSignatureKeyIdentifierThumbprintOutbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.SIGNATURE};
            securityProperties.setOutAction(actions);
            securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setSignatureUser("transmitter");
            securityProperties.setSignatureKeyIdentifier(WSSecurityTokenConstants.KeyIdentifier_ThumbprintIdentifier);
            securityProperties.setCallbackHandler(new org.apache.wss4j.stax.test.CallbackHandlerImpl());

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, "UTF-8", new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

            XPathExpression xPathExpression = getXPath("/env:Envelope/env:Header/wsse:Security/dsig:Signature/dsig:KeyInfo/wsse:SecurityTokenReference/wsse:KeyIdentifier[@ValueType='http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#ThumbprintSHA1']");
            Node node = (Node) xPathExpression.evaluate(document, XPathConstants.NODE);
            Assert.assertNotNull(node);

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Reference.getNamespaceURI(), WSSConstants.TAG_dsig_Reference.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);

            nodeList = document.getElementsByTagNameNS(WSSConstants.NS_SOAP11, WSSConstants.TAG_soap_Body_LocalName);
            Assert.assertEquals(nodeList.getLength(), 1);
            String idAttrValue = ((Element) nodeList.item(0)).getAttributeNS(WSSConstants.ATT_wsu_Id.getNamespaceURI(), WSSConstants.ATT_wsu_Id.getLocalPart());
            Assert.assertNotNull(idAttrValue);
            Assert.assertTrue(idAttrValue.length() > 0);
        }

        //done signature; now test sig-verification:
        {
            String action = WSHandlerConstants.SIGNATURE;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @Test
    public void testSignatureKeyIdentifierThumbprintInbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.SIGNATURE;
            Properties properties = new Properties();
            properties.setProperty(WSHandlerConstants.SIG_KEY_ID, "Thumbprint");
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            XPathExpression xPathExpression = getXPath("/env:Envelope/env:Header/wsse:Security/dsig:Signature/dsig:KeyInfo/wsse:SecurityTokenReference/wsse:KeyIdentifier[@ValueType='http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#ThumbprintSHA1']");
            Node node = (Node) xPathExpression.evaluate(securedDocument, XPathConstants.NODE);
            Assert.assertNotNull(node);

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
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());
        }
    }
    

    @Test
    public void testSignatureKeyIdentifierThumbprintIncludeTokenOutbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.SIGNATURE};
            securityProperties.setOutAction(actions);
            securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setSignatureUser("transmitter");
            securityProperties.setSignatureKeyIdentifier(WSSecurityTokenConstants.KeyIdentifier_ThumbprintIdentifier);
            securityProperties.setCallbackHandler(new org.apache.wss4j.stax.test.CallbackHandlerImpl());
            securityProperties.setIncludeSignatureToken(true);

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, "UTF-8", new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

            XPathExpression xPathExpression = getXPath("/env:Envelope/env:Header/wsse:Security/dsig:Signature/dsig:KeyInfo/wsse:SecurityTokenReference/wsse:KeyIdentifier[@ValueType='http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#ThumbprintSHA1']");
            Node node = (Node) xPathExpression.evaluate(document, XPathConstants.NODE);
            Assert.assertNotNull(node);

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Reference.getNamespaceURI(), WSSConstants.TAG_dsig_Reference.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);

            nodeList = document.getElementsByTagNameNS(WSSConstants.NS_SOAP11, WSSConstants.TAG_soap_Body_LocalName);
            Assert.assertEquals(nodeList.getLength(), 1);
            String idAttrValue = ((Element) nodeList.item(0)).getAttributeNS(WSSConstants.ATT_wsu_Id.getNamespaceURI(), WSSConstants.ATT_wsu_Id.getLocalPart());
            Assert.assertNotNull(idAttrValue);
            Assert.assertTrue(idAttrValue.length() > 0);
        }

        //done signature; now test sig-verification:
        {
            String action = WSHandlerConstants.SIGNATURE;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @Test
    public void testSignatureKeyIdentifierSha1Outbound() throws Exception {

        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        final SecretKey key = keyGen.generateKey();

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.SIGNATURE};
            securityProperties.setOutAction(actions);
            securityProperties.setSignatureUser("transmitter");
            securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setSignatureKeyIdentifier(WSSecurityTokenConstants.KeyIdentifier_EncryptedKeySha1Identifier);
            securityProperties.setSignatureAlgorithm("http://www.w3.org/2000/09/xmldsig#hmac-sha1");
            securityProperties.setCallbackHandler(
                    new org.apache.wss4j.stax.test.CallbackHandlerImpl(key.getEncoded()){
                        @Override
                        public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                            WSPasswordCallback pc = (WSPasswordCallback) callbacks[0];
                            pc.setKey(key.getEncoded());
                        }
                    }
            );

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, "UTF-8", new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

            XPathExpression xPathExpression =
                    getXPath("/env:Envelope/env:Header/wsse:Security/dsig:Signature/dsig:KeyInfo/" +
                            "wsse:SecurityTokenReference/wsse:KeyIdentifier[@ValueType=" +
                            "'http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#EncryptedKeySHA1']");
            Node node = (Node) xPathExpression.evaluate(document, XPathConstants.NODE);
            Assert.assertNotNull(node);

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Reference.getNamespaceURI(), WSSConstants.TAG_dsig_Reference.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);

            nodeList = document.getElementsByTagNameNS(WSSConstants.NS_SOAP11, WSSConstants.TAG_soap_Body_LocalName);
            Assert.assertEquals(nodeList.getLength(), 1);
            String idAttrValue = ((Element) nodeList.item(0)).getAttributeNS(WSSConstants.ATT_wsu_Id.getNamespaceURI(), WSSConstants.ATT_wsu_Id.getLocalPart());
            Assert.assertNotNull(idAttrValue);
            Assert.assertTrue(idAttrValue.length() > 0);
        }

        //done signature; now test sig-verification:
        {
            String action = WSHandlerConstants.SIGNATURE;
            Properties properties = new Properties();
            WSS4JCallbackHandlerImpl callbackHandler = new WSS4JCallbackHandlerImpl(key.getEncoded());
            properties.put(WSHandlerConstants.PW_CALLBACK_REF, callbackHandler);
            doInboundSecurityWithWSS4J_1(
                    documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())),
                    action, properties, true);
        }
    }

    @Test
    public void testSignatureKeyIdentifierSha1Inbound() throws Exception {

        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        SecretKey key = keyGen.generateKey();

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");

            Document doc = documentBuilderFactory.newDocumentBuilder().parse(sourceDocument);
            WSSecHeader secHeader = new WSSecHeader();
            secHeader.insertSecurityHeader(doc);

            WSSecSignature sign = new WSSecSignature();
            sign.setKeyIdentifierType(WSConstants.ENCRYPTED_KEY_SHA1_IDENTIFIER);
            sign.setSecretKey(key.getEncoded());
            sign.setSignatureAlgorithm(SignatureMethod.HMAC_SHA1);

            Document securedDocument = sign.build(doc, null, secHeader);

            //some test that we can really sure we get what we want from WSS4J
            XPathExpression xPathExpression =
                    getXPath("/env:Envelope/env:Header/wsse:Security/dsig:Signature/dsig:KeyInfo/" +
                                    "wsse:SecurityTokenReference/wsse:KeyIdentifier[@ValueType=" +
                                    "'http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#EncryptedKeySHA1']");
            Node node = (Node) xPathExpression.evaluate(securedDocument, XPathConstants.NODE);
            Assert.assertNotNull(node);

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        //done signature; now test sig-verification:
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new org.apache.wss4j.stax.test.CallbackHandlerImpl(key.getEncoded()));
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());
        }
    }

    @Test
    public void testSignatureUsePKIPathOutbound() throws Exception {
        
        // Needs BouncyCastle to work properly...
        if (Security.getProvider("BC") == null) {
            return;
        }

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.SIGNATURE};
            securityProperties.setOutAction(actions);
            securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setSignatureUser("transmitter");
            securityProperties.setUseSingleCert(false);
            securityProperties.setSignatureKeyIdentifier(WSSecurityTokenConstants.KeyIdentifier_SecurityTokenDirectReference);
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, "UTF-8", new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Reference.getNamespaceURI(), WSSConstants.TAG_dsig_Reference.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);

            nodeList = document.getElementsByTagNameNS(WSSConstants.NS_SOAP11, WSSConstants.TAG_soap_Body_LocalName);
            Assert.assertEquals(nodeList.getLength(), 1);
            String idAttrValue = ((Element) nodeList.item(0)).getAttributeNS(WSSConstants.ATT_wsu_Id.getNamespaceURI(), WSSConstants.ATT_wsu_Id.getLocalPart());
            Assert.assertNotNull(idAttrValue);
            Assert.assertTrue(idAttrValue.length() > 0);
        }

        //done signature; now test sig-verification:
        {
            String action = WSHandlerConstants.SIGNATURE;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @Test
    public void testSignatureUsePKIPathInbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.SIGNATURE;
            Properties properties = new Properties();
            properties.setProperty(WSHandlerConstants.USE_SINGLE_CERTIFICATE, "false");
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

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
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());
        }
    }

    @Test
    public void testSignatureRSAKeyValue() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.SIGNATURE};
            securityProperties.setOutAction(actions);
            securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setSignatureUser("transmitter");
            securityProperties.setSignatureKeyIdentifier(WSSecurityTokenConstants.KeyIdentifier_KeyValue);
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, "UTF-8", new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_RSAKeyValue.getNamespaceURI(), WSSConstants.TAG_dsig_RSAKeyValue.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);

            nodeList = document.getElementsByTagNameNS(WSSConstants.NS_SOAP11, WSSConstants.TAG_soap_Body_LocalName);
            Assert.assertEquals(nodeList.getLength(), 1);
            String idAttrValue = ((Element) nodeList.item(0)).getAttributeNS(WSSConstants.ATT_wsu_Id.getNamespaceURI(), WSSConstants.ATT_wsu_Id.getLocalPart());
            Assert.assertNotNull(idAttrValue);
            Assert.assertTrue(idAttrValue.length() > 0);
        }
        //done signature; now test sig-verification:
        {
            String action = WSHandlerConstants.SIGNATURE;
            Properties properties = new Properties();
            doInboundSecurityWithWSS4J_1(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action, properties, false);
        }
        //also test swssf inbound
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.addIgnoreBSPRule(BSPRule.R5421);
            securityProperties.addIgnoreBSPRule(BSPRule.R5417);
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);

            WSSecurityEventConstants.Event[] expectedSecurityEvents = new WSSecurityEventConstants.Event[]{
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.SignatureValue,
                    WSSecurityEventConstants.KeyValueToken,
                    WSSecurityEventConstants.SignedElement,
                    WSSecurityEventConstants.Operation,
            };
            final TestSecurityEventListener securityEventListener = new TestSecurityEventListener(expectedSecurityEvents);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())), null, securityEventListener);
            StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            securityEventListener.compare();

            SignedElementSecurityEvent signedElementSecurityEvent = securityEventListener.getSecurityEvent(WSSecurityEventConstants.SignedElement);
            SignatureValueSecurityEvent signatureValueSecurityEvent = securityEventListener.getSecurityEvent(WSSecurityEventConstants.SignatureValue);
            OperationSecurityEvent operationSecurityEvent = securityEventListener.getSecurityEvent(WSSecurityEventConstants.Operation);
            String signedElementCorrelationID = signedElementSecurityEvent.getCorrelationID();
            String signatureValueCorrelationID = signatureValueSecurityEvent.getCorrelationID();
            String operationCorrelationID = operationSecurityEvent.getCorrelationID();

            List<SecurityEvent> operationSecurityEvents = new ArrayList<SecurityEvent>();
            List<SecurityEvent> signedElementSecurityEvents = new ArrayList<SecurityEvent>();
            List<SecurityEvent> signatureValueSecurityEvents = new ArrayList<SecurityEvent>();

            List<SecurityEvent> securityEvents = securityEventListener.getReceivedSecurityEvents();
            for (int i = 0; i < securityEvents.size(); i++) {
                SecurityEvent securityEvent = securityEvents.get(i);
                if (securityEvent.getCorrelationID().equals(signedElementCorrelationID)) {
                    signedElementSecurityEvents.add(securityEvent);
                } else if (securityEvent.getCorrelationID().equals(signatureValueCorrelationID)) {
                    signatureValueSecurityEvents.add(securityEvent);
                } else if (securityEvent.getCorrelationID().equals(operationCorrelationID)) {
                    operationSecurityEvents.add(securityEvent);
                }
            }

            org.junit.Assert.assertEquals(3, signedElementSecurityEvents.size());
            org.junit.Assert.assertEquals(4, signatureValueSecurityEvents.size());
            org.junit.Assert.assertEquals(securityEventListener.getReceivedSecurityEvents().size(),
                    operationSecurityEvents.size() +
                            signedElementSecurityEvents.size() + signatureValueSecurityEvents.size()
            );
        }
    }

    @Test
    public void testSignatureDSAKeyValue() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.SIGNATURE};
            securityProperties.setOutAction(actions);
            securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setSignatureUser("transmitter-dsa");
            securityProperties.setSignatureKeyIdentifier(WSSecurityTokenConstants.KeyIdentifier_KeyValue);
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            securityProperties.setSignatureAlgorithm("http://www.w3.org/2000/09/xmldsig#dsa-sha1");

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, "UTF-8", new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_DSAKeyValue.getNamespaceURI(), WSSConstants.TAG_dsig_DSAKeyValue.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);

            nodeList = document.getElementsByTagNameNS(WSSConstants.NS_SOAP11, WSSConstants.TAG_soap_Body_LocalName);
            Assert.assertEquals(nodeList.getLength(), 1);
            String idAttrValue = ((Element) nodeList.item(0)).getAttributeNS(WSSConstants.ATT_wsu_Id.getNamespaceURI(), WSSConstants.ATT_wsu_Id.getLocalPart());
            Assert.assertNotNull(idAttrValue);
            Assert.assertTrue(idAttrValue.length() > 0);
        }
        //done signature; now test sig-verification:
        {
            String action = WSHandlerConstants.SIGNATURE;
            Properties properties = new Properties();
            doInboundSecurityWithWSS4J_1(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action, properties, false);
        }
        //also test swssf inbound
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.addIgnoreBSPRule(BSPRule.R5421);
            securityProperties.addIgnoreBSPRule(BSPRule.R5417);
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);
            Assert.assertNotNull(document);
        }
    }

    @Test
    public void testSignatureECKeyValue() throws Exception {
        
        if (Security.getProvider("BC") == null) {
            return;
        }

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.SIGNATURE};
            securityProperties.setOutAction(actions);
            securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setSignatureUser("transmitter-ecdsa");
            securityProperties.setSignatureKeyIdentifier(WSSecurityTokenConstants.KeyIdentifier_KeyValue);
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            securityProperties.setSignatureAlgorithm("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512");

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, "UTF-8", new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig11_ECKeyValue.getNamespaceURI(), WSSConstants.TAG_dsig11_ECKeyValue.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);

            nodeList = document.getElementsByTagNameNS(WSSConstants.NS_SOAP11, WSSConstants.TAG_soap_Body_LocalName);
            Assert.assertEquals(nodeList.getLength(), 1);
            String idAttrValue = ((Element) nodeList.item(0)).getAttributeNS(WSSConstants.ATT_wsu_Id.getNamespaceURI(), WSSConstants.ATT_wsu_Id.getLocalPart());
            Assert.assertNotNull(idAttrValue);
            Assert.assertTrue(idAttrValue.length() > 0);
        }
        //done signature; now test sig-verification:
        {
            String action = WSHandlerConstants.SIGNATURE;
            Properties properties = new Properties();
            doInboundSecurityWithWSS4J_1(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action, properties, false);
        }
        //also test swssf inbound
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.addIgnoreBSPRule(BSPRule.R5421);
            securityProperties.addIgnoreBSPRule(BSPRule.R5417);
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);
            Assert.assertNotNull(document);
        }
    }

    @Test
    public void testSignatureHMACOutputLengthInbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.SIGNATURE;
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, new Properties());

            NodeList nodeList = securedDocument.getElementsByTagNameNS(WSSConstants.TAG_dsig_SignatureMethod.getNamespaceURI(), WSSConstants.TAG_dsig_SignatureMethod.getLocalPart());
            Element hmacElement = securedDocument.createElementNS(WSSConstants.TAG_dsig_HMACOutputLength.getNamespaceURI(), WSSConstants.TAG_dsig_HMACOutputLength.getLocalPart());
            hmacElement.setTextContent("abc");
            nodeList.item(0).appendChild(hmacElement);

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
                Assert.fail("Should have thrown XMLStreamException");
            } catch (XMLStreamException e) {
                Assert.assertTrue(e.getCause() instanceof WSSecurityException);
                Assert.assertEquals(e.getCause().getMessage(), "cvc-datatype-valid.1.2.1: 'abc' is not a valid value for 'integer'.");
                Assert.assertEquals(((WSSecurityException) e.getCause()).getFaultCode(), WSSecurityException.INVALID_SECURITY);
            }
        }
    }
    
    @Test
    public void testInboundRequiredAlgorithm() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.SIGNATURE;
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, new Properties());

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        //done signature; now test sig-verification:
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.setSignatureAlgorithm(WSSConstants.NS_XMLDSIG_RSASHA1);
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());
        }
        
        // This should fail as we require another signature algorithm
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.setSignatureAlgorithm(WSSConstants.NS_XMLDSIG_HMACSHA1);
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);

            try {
                XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));
                StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);
                Assert.fail("Failure expected on the wrong signature algorithm");
            } catch (XMLStreamException e) {
                Assert.assertTrue(e.getCause() instanceof WSSecurityException);
            }
        }
    }
    
    @Test
    public void testSignaturePropertiesOutbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            Map<String, Object> config = new HashMap<String, Object>();
            config.put(ConfigurationConstants.ACTION, ConfigurationConstants.SIGNATURE);
            config.put(ConfigurationConstants.SIGNATURE_USER, "transmitter");
            config.put(ConfigurationConstants.PW_CALLBACK_REF, new CallbackHandlerImpl());
            config.put(ConfigurationConstants.SIG_PROP_FILE, "transmitter-crypto.properties");

            WSSSecurityProperties securityProperties = ConfigurationConverter.convert(config);
            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, "UTF-8", new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Reference.getNamespaceURI(), WSSConstants.TAG_dsig_Reference.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);

            nodeList = document.getElementsByTagNameNS(WSSConstants.NS_SOAP11, WSSConstants.TAG_soap_Body_LocalName);
            Assert.assertEquals(nodeList.getLength(), 1);
            String idAttrValue = ((Element) nodeList.item(0)).getAttributeNS(WSSConstants.ATT_wsu_Id.getNamespaceURI(), WSSConstants.ATT_wsu_Id.getLocalPart());
            Assert.assertNotNull(idAttrValue);
            Assert.assertTrue(idAttrValue.length() > 0);

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_c14nExcl_InclusiveNamespaces.getNamespaceURI(), WSSConstants.TAG_c14nExcl_InclusiveNamespaces.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 2);
            Assert.assertEquals(((Element) nodeList.item(0)).getAttributeNS(null, WSSConstants.ATT_NULL_PrefixList.getLocalPart()), "env");
            Assert.assertEquals(((Element) nodeList.item(1)).getAttributeNS(null, WSSConstants.ATT_NULL_PrefixList.getLocalPart()), "");
        }
        //done signature; now test sig-verification:
        {
            String action = WSHandlerConstants.SIGNATURE;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @Test
    public void testSignaturePropertiesInbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.SIGNATURE;
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, new Properties());

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        //done signature; now test sig-verification:
        {
            Map<String, Object> config = new HashMap<String, Object>();
            config.put(ConfigurationConstants.ACTION, ConfigurationConstants.SIGNATURE);
            config.put(ConfigurationConstants.SIG_VER_PROP_FILE, "transmitter-crypto.properties");

            WSSSecurityProperties securityProperties = ConfigurationConverter.convert(config);
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());
        }
    }

    @Test
    public void testElementToSignNotFound() throws Exception {
        
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.SIGNATURE};
            securityProperties.setOutAction(actions);
            securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setSignatureUser("transmitter");
            securityProperties.setTokenUser("transmitter");
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            securityProperties.addSignaturePart(
                    new SecurePart(new QName(WSSConstants.NS_WSSE10, "UsernameToken"), SecurePart.Modifier.Element)
            );
            securityProperties.addSignaturePart(
                    new SecurePart(new QName(WSSConstants.NS_SOAP11, "Body"), SecurePart.Modifier.Element)
            );

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, "UTF-8", new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));

            try {
                XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
                xmlStreamWriter.close();
                Assert.fail("Exception expected");
            } catch (XMLStreamException e) {
                org.junit.Assert.assertTrue(e.getCause() instanceof XMLSecurityException);
                org.junit.Assert.assertEquals("Part to sign not found: {http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd}UsernameToken", e.getCause().getMessage());
            }
        }
    }
}
