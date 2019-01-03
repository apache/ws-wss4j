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
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.XMLStreamWriter;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.handler.WSHandlerConstants;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.ext.WSSSecurityProperties;
import org.apache.wss4j.stax.securityToken.WSSecurityTokenConstants;
import org.apache.wss4j.stax.setup.InboundWSSec;
import org.apache.wss4j.stax.setup.OutboundWSSec;
import org.apache.wss4j.stax.setup.WSSec;
import org.apache.wss4j.stax.test.utils.StAX2DOM;
import org.apache.wss4j.stax.test.utils.XmlReaderToWriter;
import org.apache.xml.security.stax.ext.SecurePart;
import org.apache.xml.security.stax.securityEvent.SecurityEvent;
import org.apache.xml.security.stax.securityEvent.SecurityEventListener;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

import static org.junit.Assert.assertEquals;

public class HeaderOrderingTest extends AbstractTestBase {

    @Test
    public void testUsernameTokenSignedStrictHeaderOrdering() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            List<WSSConstants.Action> actions = new ArrayList<>();
            actions.add(WSSConstants.SIGNATURE);
            actions.add(WSSConstants.USERNAMETOKEN);
            securityProperties.setActions(actions);
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
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, StandardCharsets.UTF_8.name(), new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));

            NodeList securityHeaderElement = document.getElementsByTagNameNS(WSConstants.WSSE_NS, "Security");
            assertEquals(1, securityHeaderElement.getLength());
            NodeList childs = securityHeaderElement.item(0).getChildNodes();

            assertEquals(childs.getLength(), 2);
            assertEquals(childs.item(0).getLocalName(), "UsernameToken");
            assertEquals(childs.item(1).getLocalName(), "Signature");

            NodeList sigReferences = document.getElementsByTagNameNS(WSConstants.SIG_NS, "Reference");
            assertEquals(2, sigReferences.getLength());
        }

        //done UsernameToken; now verification:
        {
            String action = WSHandlerConstants.SIGNATURE + " " + WSHandlerConstants.USERNAME_TOKEN;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @Test
    public void testUsernameTokenSignedLaxHeaderOrdering() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            List<WSSConstants.Action> actions = new ArrayList<>();
            actions.add(WSSConstants.USERNAMETOKEN);
            actions.add(WSSConstants.SIGNATURE);
            securityProperties.setActions(actions);
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
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, StandardCharsets.UTF_8.name(), new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));

            NodeList securityHeaderElement = document.getElementsByTagNameNS(WSConstants.WSSE_NS, "Security");
            assertEquals(1, securityHeaderElement.getLength());
            NodeList childs = securityHeaderElement.item(0).getChildNodes();

            assertEquals(childs.getLength(), 2);
            assertEquals(childs.item(0).getLocalName(), "Signature");
            assertEquals(childs.item(1).getLocalName(), "UsernameToken");

            NodeList sigReferences = document.getElementsByTagNameNS(WSConstants.SIG_NS, "Reference");
            assertEquals(2, sigReferences.getLength());
        }

        //done UsernameToken; now verification:
        {
            String action = WSHandlerConstants.USERNAME_TOKEN + " " + WSHandlerConstants.SIGNATURE;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @Test
    public void testUsernameTokenSignedWithBSTStrictHeaderOrdering() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            List<WSSConstants.Action> actions = new ArrayList<>();
            actions.add(WSSConstants.SIGNATURE);
            actions.add(WSSConstants.USERNAMETOKEN);
            securityProperties.setActions(actions);
            securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setSignatureUser("transmitter");
            securityProperties.setTokenUser("transmitter");
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            securityProperties.setSignatureKeyIdentifier(WSSecurityTokenConstants.KEYIDENTIFIER_SECURITY_TOKEN_DIRECT_REFERENCE);
            securityProperties.addSignaturePart(
                    new SecurePart(new QName(WSSConstants.NS_WSSE10, "UsernameToken"), SecurePart.Modifier.Element)
            );
            securityProperties.addSignaturePart(
                    new SecurePart(new QName(WSSConstants.NS_SOAP11, "Body"), SecurePart.Modifier.Element)
            );

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, StandardCharsets.UTF_8.name(), new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));

            NodeList securityHeaderElement = document.getElementsByTagNameNS(WSConstants.WSSE_NS, "Security");
            assertEquals(1, securityHeaderElement.getLength());
            NodeList childs = securityHeaderElement.item(0).getChildNodes();

            assertEquals(childs.getLength(), 3);
            assertEquals(childs.item(0).getLocalName(), "UsernameToken");
            assertEquals(childs.item(1).getLocalName(), "BinarySecurityToken");
            assertEquals(childs.item(2).getLocalName(), "Signature");

            NodeList sigReferences = document.getElementsByTagNameNS(WSConstants.SIG_NS, "Reference");
            assertEquals(2, sigReferences.getLength());
        }

        //done UsernameToken; now verification:
        {
            String action = WSHandlerConstants.SIGNATURE + " " + WSHandlerConstants.USERNAME_TOKEN;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @Test
    public void testTimestampSignedStrictHeaderOrdering() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            List<WSSConstants.Action> actions = new ArrayList<>();
            actions.add(WSSConstants.SIGNATURE);
            actions.add(WSSConstants.TIMESTAMP);
            securityProperties.setActions(actions);
            securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setSignatureUser("transmitter");
            securityProperties.setTokenUser("transmitter");
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            securityProperties.addSignaturePart(
                    new SecurePart(new QName(WSSConstants.NS_WSU10, "Timestamp"), SecurePart.Modifier.Element)
            );
            securityProperties.addSignaturePart(
                    new SecurePart(new QName(WSSConstants.NS_SOAP11, "Body"), SecurePart.Modifier.Element)
            );

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, StandardCharsets.UTF_8.name(), new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));

            NodeList securityHeaderElement = document.getElementsByTagNameNS(WSConstants.WSSE_NS, "Security");
            assertEquals(1, securityHeaderElement.getLength());
            NodeList childs = securityHeaderElement.item(0).getChildNodes();

            assertEquals(childs.getLength(), 2);
            assertEquals(childs.item(0).getLocalName(), "Timestamp");
            assertEquals(childs.item(1).getLocalName(), "Signature");

            NodeList sigReferences = document.getElementsByTagNameNS(WSConstants.SIG_NS, "Reference");
            assertEquals(2, sigReferences.getLength());
        }

        //done UsernameToken; now verification:
        {
            String action = WSHandlerConstants.SIGNATURE + " " + WSHandlerConstants.TIMESTAMP;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @Test
    public void testTimestampSignedLaxHeaderOrdering() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            List<WSSConstants.Action> actions = new ArrayList<>();
            actions.add(WSSConstants.TIMESTAMP);
            actions.add(WSSConstants.SIGNATURE);
            securityProperties.setActions(actions);
            securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setSignatureUser("transmitter");
            securityProperties.setTokenUser("transmitter");
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            securityProperties.addSignaturePart(
                    new SecurePart(new QName(WSSConstants.NS_WSU10, "Timestamp"), SecurePart.Modifier.Element)
            );
            securityProperties.addSignaturePart(
                    new SecurePart(new QName(WSSConstants.NS_SOAP11, "Body"), SecurePart.Modifier.Element)
            );

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, StandardCharsets.UTF_8.name(), new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));

            NodeList securityHeaderElement = document.getElementsByTagNameNS(WSConstants.WSSE_NS, "Security");
            assertEquals(1, securityHeaderElement.getLength());
            NodeList childs = securityHeaderElement.item(0).getChildNodes();

            assertEquals(childs.getLength(), 2);
            assertEquals(childs.item(0).getLocalName(), "Signature");
            assertEquals(childs.item(1).getLocalName(), "Timestamp");

            NodeList sigReferences = document.getElementsByTagNameNS(WSConstants.SIG_NS, "Reference");
            assertEquals(2, sigReferences.getLength());
        }

        //done UsernameToken; now verification:
        {
            String action = WSHandlerConstants.TIMESTAMP + " " + WSHandlerConstants.SIGNATURE;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @Test
    public void testUsernameTokenPlusTimestampSignedStrictHeaderOrdering() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            List<WSSConstants.Action> actions = new ArrayList<>();
            actions.add(WSSConstants.SIGNATURE);
            actions.add(WSSConstants.USERNAMETOKEN);
            actions.add(WSSConstants.TIMESTAMP);
            securityProperties.setActions(actions);
            securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setSignatureUser("transmitter");
            securityProperties.setTokenUser("transmitter");
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            securityProperties.addSignaturePart(
                    new SecurePart(new QName(WSSConstants.NS_WSSE10, "UsernameToken"), SecurePart.Modifier.Element)
            );
            securityProperties.addSignaturePart(
                    new SecurePart(new QName(WSSConstants.NS_WSU10, "Timestamp"), SecurePart.Modifier.Element)
            );
            securityProperties.addSignaturePart(
                    new SecurePart(new QName(WSSConstants.NS_SOAP11, "Body"), SecurePart.Modifier.Element)
            );

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, StandardCharsets.UTF_8.name(), new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));

            NodeList securityHeaderElement = document.getElementsByTagNameNS(WSConstants.WSSE_NS, "Security");
            assertEquals(1, securityHeaderElement.getLength());
            NodeList childs = securityHeaderElement.item(0).getChildNodes();

            assertEquals(childs.getLength(), 3);
            assertEquals(childs.item(0).getLocalName(), "Timestamp");
            assertEquals(childs.item(1).getLocalName(), "UsernameToken");
            assertEquals(childs.item(2).getLocalName(), "Signature");

            NodeList sigReferences = document.getElementsByTagNameNS(WSConstants.SIG_NS, "Reference");
            assertEquals(3, sigReferences.getLength());
        }

        //done UsernameToken; now verification:
        {
            String action = WSHandlerConstants.SIGNATURE + " " + WSHandlerConstants.USERNAME_TOKEN + " " + WSHandlerConstants.TIMESTAMP;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @Test
    public void testTimestampPlusUsernameTokenSignedStrictHeaderOrdering() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            List<WSSConstants.Action> actions = new ArrayList<>();
            actions.add(WSSConstants.SIGNATURE);
            actions.add(WSSConstants.TIMESTAMP);
            actions.add(WSSConstants.USERNAMETOKEN);
            securityProperties.setActions(actions);
            securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setSignatureUser("transmitter");
            securityProperties.setTokenUser("transmitter");
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            securityProperties.addSignaturePart(
                    new SecurePart(new QName(WSSConstants.NS_WSSE10, "UsernameToken"), SecurePart.Modifier.Element)
            );
            securityProperties.addSignaturePart(
                    new SecurePart(new QName(WSSConstants.NS_WSU10, "Timestamp"), SecurePart.Modifier.Element)
            );
            securityProperties.addSignaturePart(
                    new SecurePart(new QName(WSSConstants.NS_SOAP11, "Body"), SecurePart.Modifier.Element)
            );

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, StandardCharsets.UTF_8.name(), new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));

            NodeList securityHeaderElement = document.getElementsByTagNameNS(WSConstants.WSSE_NS, "Security");
            assertEquals(1, securityHeaderElement.getLength());
            NodeList childs = securityHeaderElement.item(0).getChildNodes();

            assertEquals(childs.getLength(), 3);
            assertEquals(childs.item(0).getLocalName(), "UsernameToken");
            assertEquals(childs.item(1).getLocalName(), "Timestamp");
            assertEquals(childs.item(2).getLocalName(), "Signature");

            NodeList sigReferences = document.getElementsByTagNameNS(WSConstants.SIG_NS, "Reference");
            assertEquals(3, sigReferences.getLength());
        }

        //done UsernameToken; now verification:
        {
            String action = WSHandlerConstants.SIGNATURE + " " + WSHandlerConstants.TIMESTAMP + " " + WSHandlerConstants.USERNAME_TOKEN;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @Test
    public void testUsernameTokenPlusTimestampWithBSTSignedStrictHeaderOrdering() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            List<WSSConstants.Action> actions = new ArrayList<>();
            actions.add(WSSConstants.SIGNATURE);
            actions.add(WSSConstants.USERNAMETOKEN);
            actions.add(WSSConstants.TIMESTAMP);
            securityProperties.setActions(actions);
            securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setSignatureUser("transmitter");
            securityProperties.setTokenUser("transmitter");
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            securityProperties.setSignatureKeyIdentifier(WSSecurityTokenConstants.KEYIDENTIFIER_SECURITY_TOKEN_DIRECT_REFERENCE);
            securityProperties.addSignaturePart(
                    new SecurePart(new QName(WSSConstants.NS_WSSE10, "UsernameToken"), SecurePart.Modifier.Element)
            );
            securityProperties.addSignaturePart(
                    new SecurePart(new QName(WSSConstants.NS_WSU10, "Timestamp"), SecurePart.Modifier.Element)
            );
            securityProperties.addSignaturePart(
                    new SecurePart(new QName(WSSConstants.NS_SOAP11, "Body"), SecurePart.Modifier.Element)
            );

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, StandardCharsets.UTF_8.name(), new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));

            NodeList securityHeaderElement = document.getElementsByTagNameNS(WSConstants.WSSE_NS, "Security");
            assertEquals(1, securityHeaderElement.getLength());
            NodeList childs = securityHeaderElement.item(0).getChildNodes();

            assertEquals(childs.getLength(), 4);
            assertEquals(childs.item(0).getLocalName(), "Timestamp");
            assertEquals(childs.item(1).getLocalName(), "UsernameToken");
            assertEquals(childs.item(2).getLocalName(), "BinarySecurityToken");
            assertEquals(childs.item(3).getLocalName(), "Signature");

            NodeList sigReferences = document.getElementsByTagNameNS(WSConstants.SIG_NS, "Reference");
            assertEquals(3, sigReferences.getLength());
        }

        //done UsernameToken; now verification:
        {
            String action = WSHandlerConstants.SIGNATURE + " " + WSHandlerConstants.USERNAME_TOKEN + " " + WSHandlerConstants.TIMESTAMP;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @Test
    public void testUsernameTokenPlusTimestampSignedAndEncryptedStrictHeaderOrdering() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            List<WSSConstants.Action> actions = new ArrayList<>();
            actions.add(WSSConstants.SIGNATURE);
            actions.add(WSSConstants.ENCRYPT);
            actions.add(WSSConstants.USERNAMETOKEN);
            actions.add(WSSConstants.TIMESTAMP);
            securityProperties.setActions(actions);
            securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setSignatureUser("transmitter");
            securityProperties.setTokenUser("transmitter");
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            securityProperties.addSignaturePart(
                    new SecurePart(new QName(WSSConstants.NS_WSSE10, "UsernameToken"), SecurePart.Modifier.Element)
            );
            securityProperties.addSignaturePart(
                    new SecurePart(new QName(WSSConstants.NS_WSU10, "Timestamp"), SecurePart.Modifier.Element)
            );
            securityProperties.addSignaturePart(
                    new SecurePart(new QName(WSSConstants.NS_SOAP11, "Body"), SecurePart.Modifier.Element)
            );

            securityProperties.setEncryptionUser("receiver");
            securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.addEncryptionPart(
                    new SecurePart(new QName(WSSConstants.NS_WSSE10, "UsernameToken"), SecurePart.Modifier.Element)
            );
            securityProperties.addEncryptionPart(
                    new SecurePart(new QName(WSSConstants.NS_WSU10, "Timestamp"), SecurePart.Modifier.Element)
            );
            securityProperties.addEncryptionPart(
                    new SecurePart(new QName(WSSConstants.NS_SOAP11, "Body"), SecurePart.Modifier.Content)
            );

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, StandardCharsets.UTF_8.name(), new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));

            NodeList securityHeaderElement = document.getElementsByTagNameNS(WSConstants.WSSE_NS, "Security");
            assertEquals(1, securityHeaderElement.getLength());
            NodeList childs = securityHeaderElement.item(0).getChildNodes();

            assertEquals(childs.getLength(), 4);
            assertEquals(childs.item(0).getLocalName(), "EncryptedKey");
            assertEquals(childs.item(1).getLocalName(), "EncryptedData");
            assertEquals(childs.item(2).getLocalName(), "EncryptedData");
            assertEquals(childs.item(3).getLocalName(), "Signature");

            NodeList sigReferences = document.getElementsByTagNameNS(WSConstants.SIG_NS, "Reference");
            assertEquals(3, sigReferences.getLength());
        }

        //done UsernameToken; now verification:
        {
            String action = WSHandlerConstants.SIGNATURE  + " " + WSHandlerConstants.USERNAME_TOKEN + " " + WSHandlerConstants.TIMESTAMP + " " + WSHandlerConstants.ENCRYPT;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @Test
    public void testUsernameTokenPlusTimestampWithBSTSignedAndEncryptedStrictHeaderOrdering() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            List<WSSConstants.Action> actions = new ArrayList<>();
            actions.add(WSSConstants.SIGNATURE);
            actions.add(WSSConstants.ENCRYPT);
            actions.add(WSSConstants.USERNAMETOKEN);
            actions.add(WSSConstants.TIMESTAMP);
            securityProperties.setActions(actions);
            securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setSignatureUser("transmitter");
            securityProperties.setTokenUser("transmitter");
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            securityProperties.setSignatureKeyIdentifier(WSSecurityTokenConstants.KEYIDENTIFIER_SECURITY_TOKEN_DIRECT_REFERENCE);
            securityProperties.addSignaturePart(
                    new SecurePart(new QName(WSSConstants.NS_WSSE10, "UsernameToken"), SecurePart.Modifier.Element)
            );
            securityProperties.addSignaturePart(
                    new SecurePart(new QName(WSSConstants.NS_WSU10, "Timestamp"), SecurePart.Modifier.Element)
            );
            securityProperties.addSignaturePart(
                    new SecurePart(new QName(WSSConstants.NS_SOAP11, "Body"), SecurePart.Modifier.Element)
            );

            securityProperties.setEncryptionUser("receiver");
            securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setEncryptionKeyIdentifier(WSSecurityTokenConstants.KEYIDENTIFIER_SECURITY_TOKEN_DIRECT_REFERENCE);
            securityProperties.addEncryptionPart(
                    new SecurePart(new QName(WSSConstants.NS_WSSE10, "UsernameToken"), SecurePart.Modifier.Element)
            );
            securityProperties.addEncryptionPart(
                    new SecurePart(new QName(WSSConstants.NS_WSU10, "Timestamp"), SecurePart.Modifier.Element)
            );
            securityProperties.addEncryptionPart(
                    new SecurePart(new QName(WSSConstants.NS_SOAP11, "Body"), SecurePart.Modifier.Content)
            );

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, StandardCharsets.UTF_8.name(), new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));

            NodeList securityHeaderElement = document.getElementsByTagNameNS(WSConstants.WSSE_NS, "Security");
            assertEquals(1, securityHeaderElement.getLength());
            NodeList childs = securityHeaderElement.item(0).getChildNodes();

            assertEquals(childs.getLength(), 6);
            assertEquals(childs.item(0).getLocalName(), "BinarySecurityToken");
            assertEquals(childs.item(1).getLocalName(), "EncryptedKey");
            assertEquals(childs.item(2).getLocalName(), "EncryptedData");
            assertEquals(childs.item(3).getLocalName(), "EncryptedData");
            assertEquals(childs.item(4).getLocalName(), "BinarySecurityToken");
            assertEquals(childs.item(5).getLocalName(), "Signature");

            NodeList sigReferences = document.getElementsByTagNameNS(WSConstants.SIG_NS, "Reference");
            assertEquals(3, sigReferences.getLength());
        }

        //done UsernameToken; now verification:
        {
            String action = WSHandlerConstants.SIGNATURE  + " " + WSHandlerConstants.USERNAME_TOKEN + " " + WSHandlerConstants.TIMESTAMP + " " + WSHandlerConstants.ENCRYPT;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testSignatureConfirmationUsernameTokenTimestampStrictHeaderOrdering() throws Exception {

        Set<Integer> sigv;
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.SIGNATURE;
            Properties properties = new Properties();
            properties.setProperty(WSHandlerConstants.ENABLE_SIGNATURE_CONFIRMATION, "true");
            Map<String, Object> messageContext = doOutboundSecurityWithWSS4J_1(sourceDocument, action, properties);
            sigv = (Set<Integer>) messageContext.get(WSHandlerConstants.SEND_SIGV);
            Document securedDocument = (Document) messageContext.get(SECURED_DOCUMENT);

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_WSSE_SECURITY.getLocalPart());

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        final List<SecurityEvent> securityEventList = new ArrayList<>();
        //done signature; now test sig-verification:
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);

            SecurityEventListener securityEventListener = new SecurityEventListener() {
                @Override
                public void registerSecurityEvent(SecurityEvent securityEvent) throws WSSecurityException {
                    securityEventList.add(securityEvent);
                }
            };

            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())), new ArrayList<SecurityEvent>(), securityEventListener);

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            assertEquals(nodeList.getLength(), 1);
            assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_WSSE_SECURITY.getLocalPart());
        }

        //so we have a request generated, now do the response:
        baos = new ByteArrayOutputStream();
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            List<WSSConstants.Action> actions = new ArrayList<>();
            actions.add(WSSConstants.SIGNATURE);
            actions.add(WSSConstants.SIGNATURE_CONFIRMATION);
            actions.add(WSSConstants.USERNAMETOKEN);
            actions.add(WSSConstants.TIMESTAMP);
            securityProperties.setActions(actions);
            securityProperties.setSignatureKeyIdentifier(WSSecurityTokenConstants.KEYIDENTIFIER_SECURITY_TOKEN_DIRECT_REFERENCE);
            securityProperties.addSignaturePart(
                    new SecurePart(new QName(WSSConstants.NS_WSSE10, "UsernameToken"), SecurePart.Modifier.Element)
            );
            securityProperties.addSignaturePart(
                    new SecurePart(new QName(WSSConstants.NS_WSU10, "Timestamp"), SecurePart.Modifier.Element)
            );
            securityProperties.addSignaturePart(
                    new SecurePart(WSSConstants.TAG_WSSE11_SIG_CONF, SecurePart.Modifier.Element)
            );
            securityProperties.addSignaturePart(
                    new SecurePart(new QName(WSSConstants.NS_SOAP11, "Body"), SecurePart.Modifier.Element)
            );
            securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setSignatureUser("receiver");
            securityProperties.setTokenUser("transmitter");
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, StandardCharsets.UTF_8.name(), securityEventList);
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList securityHeaderElement = document.getElementsByTagNameNS(WSConstants.WSSE_NS, "Security");
            assertEquals(1, securityHeaderElement.getLength());
            NodeList childs = securityHeaderElement.item(0).getChildNodes();

            assertEquals(childs.getLength(), 5);
            assertEquals(childs.item(0).getLocalName(), "Timestamp");
            assertEquals(childs.item(1).getLocalName(), "UsernameToken");
            assertEquals(childs.item(2).getLocalName(), "SignatureConfirmation");
            assertEquals(childs.item(3).getLocalName(), "BinarySecurityToken");
            assertEquals(childs.item(4).getLocalName(), "Signature");

            NodeList sigReferences = document.getElementsByTagNameNS(WSConstants.SIG_NS, "Reference");
            assertEquals(4, sigReferences.getLength());
        }

        //verify SigConf response:
        {
            String action = WSHandlerConstants.SIGNATURE  + " " + WSHandlerConstants.USERNAME_TOKEN + " " + WSHandlerConstants.TIMESTAMP;
            Properties properties = new Properties();
            properties.put(WSHandlerConstants.SEND_SIGV, sigv);
            doInboundSecurityWithWSS4J_1(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action, properties, true);
        }
    }

    @Test
    public void testUsernameTokenPlusTimestampPlusSignatureWithBSTSignedAndEncryptedStrictHeaderOrdering() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            List<WSSConstants.Action> actions = new ArrayList<>();
            actions.add(WSSConstants.SIGNATURE);
            actions.add(WSSConstants.ENCRYPT);
            actions.add(WSSConstants.USERNAMETOKEN);
            actions.add(WSSConstants.TIMESTAMP);
            securityProperties.setActions(actions);
            securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setSignatureUser("transmitter");
            securityProperties.setTokenUser("transmitter");
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            securityProperties.setSignatureKeyIdentifier(WSSecurityTokenConstants.KEYIDENTIFIER_SECURITY_TOKEN_DIRECT_REFERENCE);
            securityProperties.addSignaturePart(
                    new SecurePart(new QName(WSSConstants.NS_WSSE10, "UsernameToken"), SecurePart.Modifier.Element)
            );
            securityProperties.addSignaturePart(
                    new SecurePart(new QName(WSSConstants.NS_WSU10, "Timestamp"), SecurePart.Modifier.Element)
            );
            securityProperties.addSignaturePart(
                    new SecurePart(new QName(WSSConstants.NS_SOAP11, "Body"), SecurePart.Modifier.Element)
            );

            securityProperties.setEncryptionUser("receiver");
            securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setEncryptionKeyIdentifier(WSSecurityTokenConstants.KEYIDENTIFIER_SECURITY_TOKEN_DIRECT_REFERENCE);
            securityProperties.addEncryptionPart(
                    new SecurePart(new QName(WSSConstants.NS_DSIG, "Signature"), SecurePart.Modifier.Element)
            );
            securityProperties.addEncryptionPart(
                    new SecurePart(new QName(WSSConstants.NS_WSSE10, "UsernameToken"), SecurePart.Modifier.Element)
            );
            securityProperties.addEncryptionPart(
                    new SecurePart(new QName(WSSConstants.NS_WSU10, "Timestamp"), SecurePart.Modifier.Element)
            );
            securityProperties.addEncryptionPart(
                    new SecurePart(new QName(WSSConstants.NS_SOAP11, "Body"), SecurePart.Modifier.Content)
            );

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, StandardCharsets.UTF_8.name(), new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));

            NodeList securityHeaderElement = document.getElementsByTagNameNS(WSConstants.WSSE_NS, "Security");
            assertEquals(1, securityHeaderElement.getLength());
            NodeList childs = securityHeaderElement.item(0).getChildNodes();

            assertEquals(childs.getLength(), 6);
            assertEquals(childs.item(0).getLocalName(), "BinarySecurityToken");
            assertEquals(childs.item(1).getLocalName(), "EncryptedKey");
            assertEquals(childs.item(2).getLocalName(), "EncryptedData");
            assertEquals(childs.item(3).getLocalName(), "EncryptedData");
            assertEquals(childs.item(4).getLocalName(), "BinarySecurityToken");
            assertEquals(childs.item(5).getLocalName(), "EncryptedData");

            NodeList sigReferences = document.getElementsByTagNameNS(WSConstants.SIG_NS, "Reference");
            assertEquals(0, sigReferences.getLength()); //0 because the signature is encrypted
        }

        //done UsernameToken; now verification:
        {
            String action = WSHandlerConstants.SIGNATURE  + " " + WSHandlerConstants.USERNAME_TOKEN + " " + WSHandlerConstants.TIMESTAMP + " " + WSHandlerConstants.ENCRYPT;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }
}