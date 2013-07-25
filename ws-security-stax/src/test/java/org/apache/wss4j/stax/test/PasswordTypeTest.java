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
import java.util.Properties;

import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.handler.WSHandlerConstants;
import org.apache.wss4j.stax.WSSec;
import org.apache.wss4j.stax.ext.InboundWSSec;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.ext.WSSSecurityProperties;
import org.apache.wss4j.stax.test.utils.StAX2DOM;
import org.testng.Assert;
import org.testng.annotations.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

/**
 * This is a test for processing a Username Token to enforce either a plaintext or digest
 * password type. 
 */
public class PasswordTypeTest extends AbstractTestBase {

    @Test
    public void testPasswordDigest() throws Exception {
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

        // It should pass with PASSWORD_DIGEST
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            securityProperties.setUsernameTokenPasswordType(WSSConstants.UsernameTokenPasswordType.PASSWORD_DIGEST);
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);

            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())), null);

            StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);
        }
        
        // It should pass with null
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            securityProperties.setUsernameTokenPasswordType(null);
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);

            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())), null);

            StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);
        }
        
        // It should fail with PASSWORD_TEXT
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            securityProperties.setUsernameTokenPasswordType(WSSConstants.UsernameTokenPasswordType.PASSWORD_TEXT);
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);

            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())), null);

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
    
    @Test
    public void testPasswordText() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.USERNAME_TOKEN;
            Properties properties = new Properties();
            properties.put(WSHandlerConstants.PASSWORD_TYPE, WSConstants.PW_TEXT);
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

        // It should pass with PASSWORD_TEXT
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            securityProperties.setUsernameTokenPasswordType(WSSConstants.UsernameTokenPasswordType.PASSWORD_TEXT);
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);

            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())), null);

            StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);
        }
        
        // It should pass with null
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            securityProperties.setUsernameTokenPasswordType(null);
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);

            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())), null);

            StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);
        }
        
        // It should fail with PASSWORD_DIGEST
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            securityProperties.setUsernameTokenPasswordType(WSSConstants.UsernameTokenPasswordType.PASSWORD_DIGEST);
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);

            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())), null);

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

    
}
