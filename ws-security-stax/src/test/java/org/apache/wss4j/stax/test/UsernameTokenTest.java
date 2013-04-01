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

import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.dom.handler.WSHandlerConstants;
import org.apache.wss4j.stax.securityEvent.WSSecurityEventConstants;
import org.apache.xml.security.stax.securityEvent.SecurityEvent;
import org.apache.xml.security.stax.securityEvent.SecurityEventListener;
import org.apache.wss4j.stax.WSSec;
import org.apache.wss4j.stax.ext.*;
import org.apache.wss4j.stax.securityEvent.UsernameTokenSecurityEvent;
import org.apache.wss4j.stax.test.utils.StAX2DOM;
import org.apache.wss4j.stax.test.utils.XmlReaderToWriter;
import org.testng.Assert;
import org.testng.annotations.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.XMLStreamWriter;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.GregorianCalendar;
import java.util.Properties;

public class UsernameTokenTest extends AbstractTestBase {

    @Test
    public void testDefaultConfigurationInbound() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.USERNAME_TOKEN;
            Properties properties = new Properties();
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(WSSConstants.TAG_wsse_UsernameToken.getNamespaceURI(), WSSConstants.TAG_wsse_UsernameToken.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

            nodeList = securedDocument.getElementsByTagNameNS(WSSConstants.TAG_wsse_Password.getNamespaceURI(), WSSConstants.TAG_wsse_Password.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(((Element) nodeList.item(0)).getAttributeNS(null, WSSConstants.ATT_NULL_Type.getLocalPart()), WSSConstants.UsernameTokenPasswordType.PASSWORD_DIGEST.getNamespace());

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        //done UsernameToken; now verification:
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            //securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);

            WSSecurityEventConstants.Event[] expectedSecurityEvents = new WSSecurityEventConstants.Event[]{
                    WSSecurityEventConstants.UsernameToken,
                    WSSecurityEventConstants.Operation,
            };
            final TestSecurityEventListener securityEventListener = new TestSecurityEventListener(expectedSecurityEvents);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())), null, securityEventListener);

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            securityEventListener.compare();

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_wsse_UsernameToken.getNamespaceURI(), WSSConstants.TAG_wsse_UsernameToken.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());
        }
    }

    @Test
    public void testWrongUsername() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.USERNAME_TOKEN;
            Properties properties = new Properties();
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(WSSConstants.TAG_wsse_UsernameToken.getNamespaceURI(), WSSConstants.TAG_wsse_UsernameToken.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        //done UsernameToken; now verification:
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.setCallbackHandler(new CallbackHandlerImpl("wrongUsername"));
            //securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            try {
                StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);
                Assert.fail("Expected XMLStreamException");
            } catch (XMLStreamException e) {
                Assert.assertNotNull(e.getCause());
                Assert.assertTrue(e.getCause() instanceof WSSecurityException);
                Assert.assertEquals(e.getCause().getMessage(), "The security token could not be authenticated or authorized");
                Assert.assertEquals(((WSSecurityException) e.getCause()).getFaultCode(), WSSecurityException.FAILED_AUTHENTICATION);
            }
        }
    }

    //Username can't be checked in swssf, it must be done via SecurityEvent
    @Test
    public void testInboundPW_TEXT() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.USERNAME_TOKEN;
            Properties properties = new Properties();
            properties.setProperty(WSHandlerConstants.PASSWORD_TYPE, WSConstants.PW_TEXT);
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(WSSConstants.TAG_wsse_UsernameToken.getNamespaceURI(), WSSConstants.TAG_wsse_UsernameToken.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

            nodeList = securedDocument.getElementsByTagNameNS(WSSConstants.TAG_wsse_Password.getNamespaceURI(), WSSConstants.TAG_wsse_Password.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(((Element) nodeList.item(0)).getAttributeNS(null, WSSConstants.ATT_NULL_Type.getLocalPart()), WSSConstants.UsernameTokenPasswordType.PASSWORD_TEXT.getNamespace());

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        //done UsernameToken; now verification:
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.setCallbackHandler(new CallbackHandlerImpl("username"));
            //securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);

            SecurityEventListener securityEventListener = new SecurityEventListener() {
                @Override
                public void registerSecurityEvent(SecurityEvent securityEvent) throws WSSecurityException {
                    if (securityEvent instanceof UsernameTokenSecurityEvent) {
                        UsernameTokenSecurityEvent usernameTokenSecurityEvent = (UsernameTokenSecurityEvent) securityEvent;
                        if (!"username".equals(usernameTokenSecurityEvent.getSecurityToken().getPrincipal().getName())) {
                            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "empty", "Wrong username");
                        }
                    }
                }
            };

            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())), new ArrayList<SecurityEvent>(), securityEventListener);

            try {
                StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);
                Assert.fail("Expected XMLStreamException");
            } catch (XMLStreamException e) {
                Assert.assertEquals(e.getMessage(), "org.apache.wss4j.common.ext.WSSecurityException: The security token could not be authenticated or authorized");
                Assert.assertEquals(((WSSecurityException) e.getCause()).getFaultCode(), WSSecurityException.FAILED_AUTHENTICATION);
            }
        }
    }

    //wss4j bug. PWNONE throws an NPE...
    /*@Test
    public void testInboundPWNONE() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.USERNAME_TOKEN;
            Properties properties = new Properties();
            properties.setProperty(WSHandlerConstants.PASSWORD_TYPE, WSConstants.PW_NONE);
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(WSSConstants.TAG_wsse_UsernameToken.getNamespaceURI(), WSSConstants.TAG_wsse_UsernameToken.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        //done UsernameToken; now verification:
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            //securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_wsse_UsernameToken.getNamespaceURI(), WSSConstants.TAG_wsse_UsernameToken.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());
        }
    }
    */

    @Test
    public void testReusedNonce() throws Exception {
        
        XMLGregorianCalendar created = 
            WSSConstants.datatypeFactory.newXMLGregorianCalendar(new GregorianCalendar());
        String createdString = created.toXMLFormat();
        String digest = 
            org.apache.wss4j.dom.message.token.UsernameToken.doPasswordDigest(
                "Ex2YESUvsa1qne1m6TM8XA==", createdString, "default"
            );
        
        String req = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
                "<env:Envelope xmlns:env=\"http://schemas.xmlsoap.org/soap/envelope/\">\n" +
                "    <env:Header>" +
                "       <wsse:Security xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\" xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\" env:mustUnderstand=\"1\">" +
                "           <wsse:UsernameToken wsu:Id=\"UsernameToken-1\">" +
                "               <wsse:Username>transmitter</wsse:Username>" +
                "               <wsse:Password Type=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest\">" + digest + "</wsse:Password>" +
                "               <wsse:Nonce EncodingType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary\">Ex2YESUvsa1qne1m6TM8XA==</wsse:Nonce>" +
                "               <wsu:Created>" + createdString + "</wsu:Created>" +
                "           </wsse:UsernameToken>" +
                "       </wsse:Security>\n" +
                "    </env:Header>\n" +
                "    <env:Body>\n" +
                "    </env:Body>\n" +
                "</env:Envelope>";

        WSSSecurityProperties securityProperties = new WSSSecurityProperties();
        securityProperties.setCallbackHandler(new CallbackHandlerImpl());
        InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
        XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(req.getBytes())));
        StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

        try {
            xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(req.getBytes())));
            StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);
            Assert.fail("Expected XMLStreamException");
        } catch (XMLStreamException e) {
            Assert.assertEquals(e.getMessage(), "org.apache.wss4j.common.ext.WSSecurityException: The security token could not be authenticated or authorized");
            Assert.assertEquals(((WSSecurityException) e.getCause()).getFaultCode(), WSSecurityException.FAILED_AUTHENTICATION);
        }
    }
    
    /**
     * This is a test for processing an "old" UsernameToken, i.e. one with a "Created" element that is
     * out of date
     */
    @Test
    public void testOldUsernameToken() throws Exception {
        
        GregorianCalendar createdCalendar = new GregorianCalendar();
        createdCalendar.add(Calendar.SECOND, -301);
        XMLGregorianCalendar created = 
            WSSConstants.datatypeFactory.newXMLGregorianCalendar(createdCalendar);
        String createdString = created.toXMLFormat();
        
        String digest = 
            org.apache.wss4j.dom.message.token.UsernameToken.doPasswordDigest(
                "Ex2YEKVvsa1qne1m6TM8XA==", createdString, "default"
            );
        
        String req = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
                "<env:Envelope xmlns:env=\"http://schemas.xmlsoap.org/soap/envelope/\">\n" +
                "    <env:Header>" +
                "       <wsse:Security xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\" xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\" env:mustUnderstand=\"1\">" +
                "           <wsse:UsernameToken wsu:Id=\"UsernameToken-1\">" +
                "               <wsse:Username>transmitter</wsse:Username>" +
                "               <wsse:Password Type=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest\">" + digest + "</wsse:Password>" +
                "               <wsse:Nonce EncodingType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary\">Ex2YEKVvsa1qne1m6TM8XA==</wsse:Nonce>" +
                "               <wsu:Created>" + createdString + "</wsu:Created>" +
                "           </wsse:UsernameToken>" +
                "       </wsse:Security>\n" +
                "    </env:Header>\n" +
                "    <env:Body>\n" +
                "    </env:Body>\n" +
                "</env:Envelope>";

        WSSSecurityProperties securityProperties = new WSSSecurityProperties();
        securityProperties.setCallbackHandler(new CallbackHandlerImpl());
        InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);

        try {
            XMLStreamReader xmlStreamReader = 
                wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(req.getBytes())));
            StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);
            Assert.fail("Expected XMLStreamException");
        } catch (XMLStreamException e) {
            Assert.assertEquals(e.getMessage(), "org.apache.wss4j.common.ext.WSSecurityException: The message has expired");
            Assert.assertEquals(((WSSecurityException) e.getCause()).getFaultCode(), WSSecurityException.MESSAGE_EXPIRED);
        }
    }

    /** 
     * This is a test for processing a UsernameToken where the "Created" element is in the (near)
     * future. It should be accepted by default when it is created 30 seconds in the future.
     */
    @Test
    public void testNearFutureCreated() throws Exception {
        GregorianCalendar createdCalendar = new GregorianCalendar();
        createdCalendar.add(Calendar.SECOND, 30);
        XMLGregorianCalendar created = 
            WSSConstants.datatypeFactory.newXMLGregorianCalendar(createdCalendar);
        String createdString = created.toXMLFormat();
        
        String digest = 
            org.apache.wss4j.dom.message.token.UsernameToken.doPasswordDigest(
                "Ex2YEKVvSa1qne1m6TM8XA==", createdString, "default"
            );
        
        String req = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
                "<env:Envelope xmlns:env=\"http://schemas.xmlsoap.org/soap/envelope/\">\n" +
                "    <env:Header>" +
                "       <wsse:Security xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\" xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\" env:mustUnderstand=\"1\">" +
                "           <wsse:UsernameToken wsu:Id=\"UsernameToken-1\">" +
                "               <wsse:Username>transmitter</wsse:Username>" +
                "               <wsse:Password Type=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest\">" + digest + "</wsse:Password>" +
                "               <wsse:Nonce EncodingType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary\">Ex2YEKVvSa1qne1m6TM8XA==</wsse:Nonce>" +
                "               <wsu:Created>" + createdString + "</wsu:Created>" +
                "           </wsse:UsernameToken>" +
                "       </wsse:Security>\n" +
                "    </env:Header>\n" +
                "    <env:Body>\n" +
                "    </env:Body>\n" +
                "</env:Envelope>";

        WSSSecurityProperties securityProperties = new WSSSecurityProperties();
        securityProperties.setCallbackHandler(new CallbackHandlerImpl());
        InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
        XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(req.getBytes())));
        StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);
    }
    
    /** 
     * This is a test for processing a UsernameToken where the "Created" element is in the future.
     * A UsernameToken that is 120 seconds in the future should be rejected by default.
     */
    @Test
    public void testFutureCreated() throws Exception {
        GregorianCalendar createdCalendar = new GregorianCalendar();
        createdCalendar.add(Calendar.SECOND, 120);
        XMLGregorianCalendar created = 
            WSSConstants.datatypeFactory.newXMLGregorianCalendar(createdCalendar);
        String createdString = created.toXMLFormat();
        
        String digest = 
            org.apache.wss4j.dom.message.token.UsernameToken.doPasswordDigest(
                "Ex2YEKVvsa1Qne1m6TM8XA==", createdString, "default"
            );
        
        String req = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
                "<env:Envelope xmlns:env=\"http://schemas.xmlsoap.org/soap/envelope/\">\n" +
                "    <env:Header>" +
                "       <wsse:Security xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\" xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\" env:mustUnderstand=\"1\">" +
                "           <wsse:UsernameToken wsu:Id=\"UsernameToken-1\">" +
                "               <wsse:Username>transmitter</wsse:Username>" +
                "               <wsse:Password Type=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest\">" + digest + "</wsse:Password>" +
                "               <wsse:Nonce EncodingType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary\">Ex2YEKVvsa1Qne1m6TM8XA==</wsse:Nonce>" +
                "               <wsu:Created>" + createdString + "</wsu:Created>" +
                "           </wsse:UsernameToken>" +
                "       </wsse:Security>\n" +
                "    </env:Header>\n" +
                "    <env:Body>\n" +
                "    </env:Body>\n" +
                "</env:Envelope>";

        WSSSecurityProperties securityProperties = new WSSSecurityProperties();
        securityProperties.setCallbackHandler(new CallbackHandlerImpl());
        InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);

        try {
            XMLStreamReader xmlStreamReader = 
                wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(req.getBytes())));
            StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);
            Assert.fail("Expected XMLStreamException");
        } catch (XMLStreamException e) {
            Assert.assertEquals(e.getMessage(), "org.apache.wss4j.common.ext.WSSecurityException: The message has expired");
            Assert.assertEquals(((WSSecurityException) e.getCause()).getFaultCode(), WSSecurityException.MESSAGE_EXPIRED);
        }
    }
    
    @Test
    public void testDefaultConfigurationOutbound() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.USERNAMETOKEN};
            securityProperties.setOutAction(actions);
            securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setTokenUser("transmitter");
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, "UTF-8", new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_wsse_UsernameToken.getNamespaceURI(), WSSConstants.TAG_wsse_UsernameToken.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_wsse_Password.getNamespaceURI(), WSSConstants.TAG_wsse_Password.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(((Element) nodeList.item(0)).getAttributeNS(null, WSSConstants.ATT_NULL_Type.getLocalPart()), WSSConstants.UsernameTokenPasswordType.PASSWORD_DIGEST.getNamespace());
        }

        //done UsernameToken; now verification:
        {
            String action = WSHandlerConstants.USERNAME_TOKEN;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @Test
    public void testOutboundPW_NONE() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.USERNAMETOKEN};
            securityProperties.setOutAction(actions);
            securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setTokenUser("transmitter");
            securityProperties.setUsernameTokenPasswordType(WSSConstants.UsernameTokenPasswordType.PASSWORD_NONE);
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, "UTF-8", new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_wsse_UsernameToken.getNamespaceURI(), WSSConstants.TAG_wsse_UsernameToken.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_wsse_Password.getNamespaceURI(), WSSConstants.TAG_wsse_Password.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 0);
        }

        //done UsernameToken; now verification:
        {
            String action = WSHandlerConstants.USERNAME_TOKEN;
            
            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            Properties properties = new Properties();
            properties.put(WSHandlerConstants.ALLOW_USERNAMETOKEN_NOPASSWORD, "true");
            doInboundSecurityWithWSS4J_1(document, action, properties, false);
        }
    }

    @Test
    public void testOutboundPW_TEXT() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.USERNAMETOKEN};
            securityProperties.setOutAction(actions);
            securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setTokenUser("transmitter");
            securityProperties.setUsernameTokenPasswordType(WSSConstants.UsernameTokenPasswordType.PASSWORD_TEXT);
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, "UTF-8", new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_wsse_UsernameToken.getNamespaceURI(), WSSConstants.TAG_wsse_UsernameToken.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_wsse_Password.getNamespaceURI(), WSSConstants.TAG_wsse_Password.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(((Element) nodeList.item(0)).getAttributeNS(null, WSSConstants.ATT_NULL_Type.getLocalPart()), WSSConstants.UsernameTokenPasswordType.PASSWORD_TEXT.getNamespace());
        }

        //done UsernameToken; now verification:
        {
            String action = WSHandlerConstants.USERNAME_TOKEN;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @Test
    public void testOutboundSign() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.USERNAMETOKEN_SIGNED};
            securityProperties.setOutAction(actions);
            securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setTokenUser("transmitter");
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, "UTF-8", new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_wsse_UsernameToken.getNamespaceURI(), WSSConstants.TAG_wsse_UsernameToken.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_wsse_Password.getNamespaceURI(), WSSConstants.TAG_wsse_Password.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(((Element) nodeList.item(0)).getAttributeNS(null, WSSConstants.ATT_NULL_Type.getLocalPart()), WSSConstants.UsernameTokenPasswordType.PASSWORD_DIGEST.getNamespace());

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Reference.getNamespaceURI(), WSSConstants.TAG_dsig_Reference.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);

            nodeList = document.getElementsByTagNameNS(WSSConstants.NS_SOAP11, WSSConstants.TAG_soap_Body_LocalName);
            Assert.assertEquals(nodeList.getLength(), 1);
            String idAttrValue = ((Element) nodeList.item(0)).getAttributeNS(WSSConstants.ATT_wsu_Id.getNamespaceURI(), WSSConstants.ATT_wsu_Id.getLocalPart());
            Assert.assertNotNull(idAttrValue);
            Assert.assertTrue(idAttrValue.length() > 0);
        }

        //done UsernameToken; now verification:
        {
            String action = WSHandlerConstants.SIGN_WITH_UT_KEY + " " + WSHandlerConstants.USERNAME_TOKEN;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @Test
    public void testInboundOutboundPW_NONE() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.USERNAMETOKEN};
            securityProperties.setOutAction(actions);
            securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setTokenUser("transmitter");
            securityProperties.setUsernameTokenPasswordType(WSSConstants.UsernameTokenPasswordType.PASSWORD_NONE);
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, "UTF-8", new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document securedDocument = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = securedDocument.getElementsByTagNameNS(WSSConstants.TAG_wsse_UsernameToken.getNamespaceURI(), WSSConstants.TAG_wsse_UsernameToken.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

            nodeList = securedDocument.getElementsByTagNameNS(WSSConstants.TAG_wsse_Password.getNamespaceURI(), WSSConstants.TAG_wsse_Password.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 0);
        }

        //done UsernameToken; now verification:
        
        // Failure expected on no password
        try {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));
            
            xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));
            StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);
            Assert.fail("Expected XMLStreamException");
        } catch (XMLStreamException e) {
            Assert.assertEquals(e.getMessage(), "org.apache.wss4j.common.ext.WSSecurityException: The security token could not be authenticated or authorized");
            Assert.assertEquals(((WSSecurityException) e.getCause()).getFaultCode(), WSSecurityException.FAILED_AUTHENTICATION);
        }
        
        // Now set the appropriate boolean and it should pass
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.setAllowUsernameTokenNoPassword(true);
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_wsse_UsernameToken.getNamespaceURI(), WSSConstants.TAG_wsse_UsernameToken.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());
        }
    }
}
