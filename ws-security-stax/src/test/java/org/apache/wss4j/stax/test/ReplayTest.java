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

import org.apache.wss4j.common.cache.ReplayCache;
import org.apache.wss4j.common.saml.bean.ConditionsBean;
import org.apache.wss4j.common.saml.builder.SAML2Constants;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.handler.WSHandlerConstants;
import org.apache.wss4j.stax.WSSec;
import org.apache.wss4j.stax.ext.InboundWSSec;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.ext.WSSSecurityProperties;
import org.apache.wss4j.stax.test.saml.SAML2CallbackHandler;
import org.apache.wss4j.stax.test.utils.StAX2DOM;
import org.apache.wss4j.stax.validate.SamlTokenValidatorImpl;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.junit.Assert;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

public class ReplayTest extends AbstractTestBase {

    @Test
    public void testReplayedTimestamp() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.SIGNATURE + " " + WSHandlerConstants.TIMESTAMP;
            Properties properties = new Properties();
            properties.setProperty(WSHandlerConstants.SIGNATURE_PARTS, "{Element}{" + WSConstants.WSU_NS + "}Timestamp;");
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        //done signature; now test sig-verification:
        ReplayCache replayCache = null;
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            replayCache = securityProperties.getTimestampReplayCache();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());
        }
        
        //done signature; now test sig-verification:
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.setTimestampReplayCache(replayCache);
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties, false, true);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            try {
                StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);
                Assert.fail("Exception expected");
            } catch (XMLStreamException e) {
                org.junit.Assert.assertTrue(e.getCause() instanceof XMLSecurityException);
                org.junit.Assert.assertEquals("The message has expired", e.getCause().getMessage());
            }
        }
    }
    
    @Test
    public void testUsernameToken() throws Exception {

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

        //done UsernameToken; now test verification:
        ReplayCache replayCache = null;
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            replayCache = securityProperties.getNonceReplayCache();
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_wsse_UsernameToken.getNamespaceURI(), WSSConstants.TAG_wsse_UsernameToken.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());
        }
        
        //done UsernameToken; now test verification:
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.setNonceReplayCache(replayCache);
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            try {
                StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);
                Assert.fail("Exception expected");
            } catch (XMLStreamException e) {
                org.junit.Assert.assertTrue(e.getCause() instanceof XMLSecurityException);
            }
        }
    }
    
    /**
     * Test that creates, sends and processes an unsigned SAML 2 authentication assertion. This
     * is just a sanity test to make sure that it is possible to send the SAML token twice, as
     * no "OneTimeUse" Element is defined there is no problem with replaying it.
     * with a OneTimeUse Element
     */
    @org.junit.Test
    public void testEhCacheReplayedSAML2() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
            callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
            callbackHandler.setConfirmationMethod(SAML2Constants.CONF_BEARER);
            callbackHandler.setIssuer("www.example.com");
            callbackHandler.setSignAssertion(false);

            ConditionsBean conditions = new ConditionsBean();
            conditions.setTokenPeriodMinutes(5);
            callbackHandler.setConditions(conditions);

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.SAML_TOKEN_UNSIGNED;
            Properties properties = new Properties();
            properties.put(WSHandlerConstants.SAML_CALLBACK_REF, callbackHandler);
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        // process SAML Token
        ReplayCache replayCache = null;
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            
            SamlTokenValidatorImpl validator = new SamlTokenValidatorImpl();
            validator.setRequireBearerSignature(false);
            securityProperties.addValidator(WSSConstants.TAG_saml2_Assertion, validator);
            securityProperties.addValidator(WSSConstants.TAG_saml_Assertion, validator);
            
            replayCache = securityProperties.getSamlOneTimeUseReplayCache();
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);
            Assert.assertNotNull(document);
        }
        
        // now process SAML Token again
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            
            SamlTokenValidatorImpl validator = new SamlTokenValidatorImpl();
            validator.setRequireBearerSignature(false);
            securityProperties.addValidator(WSSConstants.TAG_saml2_Assertion, validator);
            securityProperties.addValidator(WSSConstants.TAG_saml_Assertion, validator);
            
            securityProperties.setSamlOneTimeUseReplayCache(replayCache);
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);
            Assert.assertNotNull(document);
        }
    }
    
    /**
     * Test that creates, sends and processes an unsigned SAML 2 authentication assertion
     * with a OneTimeUse Element
     */
    @org.junit.Test
    public void testEhCacheReplayedSAML2OneTimeUse() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
            callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
            callbackHandler.setConfirmationMethod(SAML2Constants.CONF_BEARER);
            callbackHandler.setIssuer("www.example.com");
            callbackHandler.setSignAssertion(false);

            ConditionsBean conditions = new ConditionsBean();
            conditions.setTokenPeriodMinutes(5);
            conditions.setOneTimeUse(true);
            callbackHandler.setConditions(conditions);

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.SAML_TOKEN_UNSIGNED;
            Properties properties = new Properties();
            properties.put(WSHandlerConstants.SAML_CALLBACK_REF, callbackHandler);
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        // process SAML Token
        ReplayCache replayCache = null;
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            
            SamlTokenValidatorImpl validator = new SamlTokenValidatorImpl();
            validator.setRequireBearerSignature(false);
            securityProperties.addValidator(WSSConstants.TAG_saml2_Assertion, validator);
            securityProperties.addValidator(WSSConstants.TAG_saml_Assertion, validator);
            
            replayCache = securityProperties.getSamlOneTimeUseReplayCache();
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);
            Assert.assertNotNull(document);
        }
        
        // now process SAML Token again
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            
            SamlTokenValidatorImpl validator = new SamlTokenValidatorImpl();
            validator.setRequireBearerSignature(false);
            securityProperties.addValidator(WSSConstants.TAG_saml2_Assertion, validator);
            securityProperties.addValidator(WSSConstants.TAG_saml_Assertion, validator);
            
            securityProperties.setSamlOneTimeUseReplayCache(replayCache);
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            try {
                StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);
                Assert.fail("Exception expected");
            } catch (XMLStreamException e) {
                org.junit.Assert.assertTrue(e.getCause() instanceof XMLSecurityException);
            }
        }
    }
    
}
