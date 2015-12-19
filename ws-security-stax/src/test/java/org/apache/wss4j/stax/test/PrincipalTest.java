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
import java.security.Principal;
import java.util.Properties;

import javax.security.auth.x500.X500Principal;
import javax.xml.stream.XMLStreamReader;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.wss4j.common.bsp.BSPRule;
import org.apache.wss4j.common.principal.*;
import org.apache.wss4j.stax.securityToken.KeyValueSecurityToken;
import org.apache.wss4j.stax.securityToken.SamlSecurityToken;
import org.apache.wss4j.stax.securityToken.UsernameSecurityToken;
import org.apache.wss4j.stax.securityToken.X509SecurityToken;
import org.apache.wss4j.stax.setup.InboundWSSec;
import org.apache.wss4j.stax.setup.WSSec;
import org.apache.wss4j.stax.securityEvent.*;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.apache.wss4j.dom.handler.WSHandlerConstants;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.ext.WSSSecurityProperties;
import org.apache.wss4j.stax.test.saml.SAML1CallbackHandler;
import org.apache.wss4j.stax.test.utils.StAX2DOM;
import org.junit.Assert;
import org.junit.Test;

/**
 * A test for various Principals...
 */
public class PrincipalTest extends AbstractTestBase {

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

            StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            // Check principal
            UsernameTokenSecurityEvent event =
                (UsernameTokenSecurityEvent)securityEventListener.getSecurityEvent(WSSecurityEventConstants.UsernameToken);
            Assert.assertNotNull(event);
            UsernameSecurityToken usernameSecurityToken = event.getSecurityToken();
            Principal principal = usernameSecurityToken.getPrincipal();
            Assert.assertTrue(principal instanceof UsernameTokenPrincipal);
            UsernameTokenPrincipal usernameTokenPrincipal = (UsernameTokenPrincipal)principal;
            Assert.assertTrue("transmitter".equals(usernameTokenPrincipal.getName()));
            Assert.assertTrue(usernameTokenPrincipal.getCreatedTime() != null);
            Assert.assertTrue(usernameTokenPrincipal.getNonce() != null);
            Assert.assertTrue(usernameTokenPrincipal.getPassword() != null);
            Assert.assertTrue(usernameTokenPrincipal.isPasswordDigest());
            Assert.assertTrue(WSSConstants.NS_PASSWORD_DIGEST.equals(usernameTokenPrincipal.getPasswordType()));
        }
    }

    @Test
    public void testSAMLToken() throws Exception {

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
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);

            WSSecurityEventConstants.Event[] expectedSecurityEvents = new WSSecurityEventConstants.Event[]{
                WSSecurityEventConstants.SamlToken,
                WSSecurityEventConstants.Operation,
            };
            final TestSecurityEventListener securityEventListener = new TestSecurityEventListener(expectedSecurityEvents);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())), null, securityEventListener);

            StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            // Check principal
            SamlTokenSecurityEvent event =
                (SamlTokenSecurityEvent)securityEventListener.getSecurityEvent(WSSecurityEventConstants.SamlToken);
            Assert.assertNotNull(event);
            SamlSecurityToken token = event.getSecurityToken();

            Principal principal = token.getPrincipal();
            Assert.assertTrue(principal instanceof SAMLTokenPrincipal);
            Assert.assertTrue(principal.getName().contains("uid=joe"));
            Assert.assertTrue(((SAMLTokenPrincipal)principal).getToken() != null);
        }
    }

    @Test
    public void testX509Certificate() throws Exception {

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

            WSSecurityEventConstants.Event[] expectedSecurityEvents = new WSSecurityEventConstants.Event[]{
                WSSecurityEventConstants.X509Token,
                WSSecurityEventConstants.Operation,
            };
            final TestSecurityEventListener securityEventListener = new TestSecurityEventListener(expectedSecurityEvents);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())), null, securityEventListener);

            StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            // Check principal
            X509TokenSecurityEvent event =
                (X509TokenSecurityEvent)securityEventListener.getSecurityEvent(WSSecurityEventConstants.X509Token);
            Assert.assertNotNull(event);
            X509SecurityToken token = event.getSecurityToken();

            Principal principal = token.getPrincipal();
            Assert.assertTrue(principal instanceof X500Principal);
        }
    }

    @Test
    public void testRSAKeyValue() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.SIGNATURE;
            Properties properties = new Properties();
            properties.put(WSHandlerConstants.SIG_KEY_ID, "KeyValue");
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
            securityProperties.addIgnoreBSPRule(BSPRule.R5417);
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);

            WSSecurityEventConstants.Event[] expectedSecurityEvents = new WSSecurityEventConstants.Event[]{
                    WSSecurityEventConstants.KeyValueToken,
                    WSSecurityEventConstants.Operation,
            };
            final TestSecurityEventListener securityEventListener = new TestSecurityEventListener(expectedSecurityEvents);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())), null, securityEventListener);

            StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            // Check principal
            KeyValueTokenSecurityEvent event =
                    (KeyValueTokenSecurityEvent)securityEventListener.getSecurityEvent(WSSecurityEventConstants.KeyValueToken);
            Assert.assertNotNull(event);
            KeyValueSecurityToken token = event.getSecurityToken();

            Principal principal = token.getPrincipal();
            Assert.assertTrue(principal instanceof PublicKeyPrincipal);
        }
    }

    @Test
    public void testDSAKeyValue() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.SIGNATURE;
            Properties properties = new Properties();
            properties.put(WSHandlerConstants.SIG_KEY_ID, "KeyValue");
            properties.put(WSHandlerConstants.SIGNATURE_USER, "transmitter-dsa");
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
            securityProperties.addIgnoreBSPRule(BSPRule.R5417);
            securityProperties.addIgnoreBSPRule(BSPRule.R5421);
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);

            WSSecurityEventConstants.Event[] expectedSecurityEvents = new WSSecurityEventConstants.Event[]{
                    WSSecurityEventConstants.KeyValueToken,
                    WSSecurityEventConstants.Operation,
            };
            final TestSecurityEventListener securityEventListener = new TestSecurityEventListener(expectedSecurityEvents);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())), null, securityEventListener);

            StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            // Check principal
            KeyValueTokenSecurityEvent event =
                    (KeyValueTokenSecurityEvent)securityEventListener.getSecurityEvent(WSSecurityEventConstants.KeyValueToken);
            Assert.assertNotNull(event);
            KeyValueSecurityToken token = event.getSecurityToken();

            Principal principal = token.getPrincipal();
            Assert.assertTrue(principal instanceof PublicKeyPrincipal);
        }
    }

    @Test
    public void testECKeyValue() throws Exception {

        //
        // This test fails with the IBM JDK and with JDK 1.8
        // TODO - Re-enable with JDK 1.8 when we fix Santuario
        //
        if ("IBM Corporation".equals(System.getProperty("java.vendor"))
            || System.getProperty("java.version") != null
                &&  (System.getProperty("java.version").startsWith("1.8")
                    || System.getProperty("java.version").startsWith("1.6"))) {
            return;
        }

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.SIGNATURE;
            Properties properties = new Properties();
            properties.put(WSHandlerConstants.SIG_KEY_ID, "KeyValue");
            properties.put(WSHandlerConstants.SIGNATURE_USER, "transmitter-ecdsa");
            properties.put(WSHandlerConstants.SIG_ALGO, "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512");
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
            securityProperties.addIgnoreBSPRule(BSPRule.R5417);
            securityProperties.addIgnoreBSPRule(BSPRule.R5421);
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);

            WSSecurityEventConstants.Event[] expectedSecurityEvents = new WSSecurityEventConstants.Event[]{
                    WSSecurityEventConstants.KeyValueToken,
                    WSSecurityEventConstants.Operation,
            };
            final TestSecurityEventListener securityEventListener = new TestSecurityEventListener(expectedSecurityEvents);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())), null, securityEventListener);

            StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            // Check principal
            KeyValueTokenSecurityEvent event =
                    (KeyValueTokenSecurityEvent)securityEventListener.getSecurityEvent(WSSecurityEventConstants.KeyValueToken);
            Assert.assertNotNull(event);
            KeyValueSecurityToken token = event.getSecurityToken();

            Principal principal = token.getPrincipal();
            Assert.assertTrue(principal instanceof PublicKeyPrincipal);
        }
    }
}
