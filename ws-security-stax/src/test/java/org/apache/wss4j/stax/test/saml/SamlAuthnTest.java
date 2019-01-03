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
import java.util.Properties;

import javax.security.auth.callback.CallbackHandler;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.wss4j.common.saml.builder.SAML1Constants;
import org.apache.wss4j.common.saml.builder.SAML2Constants;
import org.apache.wss4j.dom.handler.WSHandlerConstants;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.ext.WSSSecurityProperties;
import org.apache.wss4j.stax.setup.InboundWSSec;
import org.apache.wss4j.stax.setup.WSSec;
import org.apache.wss4j.stax.test.AbstractTestBase;
import org.apache.wss4j.stax.test.utils.StAX2DOM;
import org.joda.time.DateTime;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

/**
 * Some tests for SAML Authentication Assertions
 */
public class SamlAuthnTest extends AbstractTestBase {

    private static final String IP_ADDRESS = "127.0.0.1"; //NOPMD

    @Test
    public void testSAML1AuthnAssertion() throws Exception {

        SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
        callbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHN);
        callbackHandler.setConfirmationMethod(SAML1Constants.CONF_HOLDER_KEY);
        callbackHandler.setIssuer("www.example.com");

        createDOMMessageAndVerifyStAX(callbackHandler, true);
    }

    @Test
    public void testSAML2AuthnAssertion() throws Exception {

        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
        callbackHandler.setConfirmationMethod(SAML2Constants.CONF_HOLDER_KEY);
        callbackHandler.setIssuer("www.example.com");

        createDOMMessageAndVerifyStAX(callbackHandler, true);
    }

    @Test
    public void testSAML1FutureAuthnInstant() throws Exception {

        SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
        callbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHN);
        callbackHandler.setConfirmationMethod(SAML1Constants.CONF_HOLDER_KEY);
        callbackHandler.setIssuer("www.example.com");

        callbackHandler.setAuthenticationInstant(new DateTime().plusMinutes(70));

        createDOMMessageAndVerifyStAX(callbackHandler, false);
    }

    @Test
    public void testSAML2FutureAuthnInstant() throws Exception {

        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
        callbackHandler.setConfirmationMethod(SAML2Constants.CONF_HOLDER_KEY);
        callbackHandler.setIssuer("www.example.com");

        callbackHandler.setAuthenticationInstant(new DateTime().plusMinutes(70));

        createDOMMessageAndVerifyStAX(callbackHandler, false);
    }

    @Test
    public void testSAML2StaleSessionNotOnOrAfter() throws Exception {

        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
        callbackHandler.setConfirmationMethod(SAML2Constants.CONF_HOLDER_KEY);
        callbackHandler.setIssuer("www.example.com");

        callbackHandler.setSessionNotOnOrAfter(new DateTime().minusMinutes(70));

        createDOMMessageAndVerifyStAX(callbackHandler, false);
    }

    @Test
    public void testSAML1ValidSubjectLocality() throws Exception {

        SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
        callbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHN);
        callbackHandler.setConfirmationMethod(SAML1Constants.CONF_HOLDER_KEY);
        callbackHandler.setIssuer("www.example.com");

        callbackHandler.setSubjectLocality(IP_ADDRESS, "xyz.ws.apache.org");

        createDOMMessageAndVerifyStAX(callbackHandler, true);
    }

    @Test
    public void testSAML2ValidSubjectLocality() throws Exception {

        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
        callbackHandler.setConfirmationMethod(SAML2Constants.CONF_HOLDER_KEY);
        callbackHandler.setIssuer("www.example.com");

        callbackHandler.setSubjectLocality(IP_ADDRESS, "xyz.ws.apache.org");

        createDOMMessageAndVerifyStAX(callbackHandler, true);
    }

    @Test
    public void testSAML1InvalidSubjectLocality() throws Exception {

        SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
        callbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHN);
        callbackHandler.setConfirmationMethod(SAML1Constants.CONF_HOLDER_KEY);
        callbackHandler.setIssuer("www.example.com");

        callbackHandler.setSubjectLocality("xyz.ws.apache.org", "xyz.ws.apache.org");

        createDOMMessageAndVerifyStAX(callbackHandler, false);
    }

    @Test
    public void testSAML2InvalidSubjectLocality() throws Exception {

        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
        callbackHandler.setConfirmationMethod(SAML2Constants.CONF_HOLDER_KEY);
        callbackHandler.setIssuer("www.example.com");

        callbackHandler.setSubjectLocality("xyz.ws.apache.org", "xyz.ws.apache.org");

        createDOMMessageAndVerifyStAX(callbackHandler, false);
    }

    private void createDOMMessageAndVerifyStAX(
        CallbackHandler samlCallbackHandler, boolean success
    ) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.SAML_TOKEN_SIGNED;
            Properties properties = new Properties();
            properties.put(WSHandlerConstants.SAML_CALLBACK_REF, samlCallbackHandler);
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            assertEquals(nodeList.getLength(), 2);
            assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_SAML_ASSERTION.getLocalPart());
            assertEquals(nodeList.item(1).getParentNode().getLocalName(), WSSConstants.TAG_WSSE_SECURITY.getLocalPart());

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
                Document document =
                    StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);
                if (!success) {
                    fail("XMLStreamException expected");
                }
                assertNotNull(document);
            } catch (XMLStreamException e) {
                assertFalse(success);
                assertNotNull(e.getCause());
            }
        }
    }

}