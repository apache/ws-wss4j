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
package org.apache.wss4j.policy.stax.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.wss4j.common.bsp.BSPRule;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.policy.stax.enforcer.PolicyEnforcer;
import org.apache.wss4j.policy.stax.enforcer.PolicyInputProcessor;
import org.apache.wss4j.api.stax.ext.WSSConstants;
import org.apache.wss4j.api.stax.ext.WSSSecurityProperties;
import org.apache.wss4j.stax.impl.securityToken.HttpsSecurityTokenImpl;
import org.apache.wss4j.api.stax.securityEvent.HttpsTokenSecurityEvent;
import org.apache.wss4j.api.stax.securityToken.WSSecurityTokenConstants;
import org.apache.wss4j.stax.test.CallbackHandlerImpl;
import org.apache.xml.security.stax.ext.SecurePart;
import org.apache.xml.security.stax.securityEvent.SecurityEvent;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class TransportBindingIntegrationTest extends AbstractPolicyTestBase {

    @Test
    public void testIncludeTimestampPolicy() throws Exception {

        String policyString =
                "<wsp:ExactlyOne xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\" " +
                        "xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\">\n" +
                        "            <wsp:All>\n" +
                        "                <sp:TransportBinding>\n" +
                        "                    <wsp:Policy>\n" +
                        "                        <sp:TransportToken>\n" +
                        "                            <wsp:Policy>\n" +
                        "                                <sp:HttpsToken>\n" +
                        "                                    <sp:IssuerName>transmitter</sp:IssuerName>\n" +
                        "                                    <wsp:Policy>\n" +
                        "                                        <sp:HttpBasicAuthentication/>\n" +
                        "                                    </wsp:Policy>\n" +
                        "                                </sp:HttpsToken>\n" +
                        "                            </wsp:Policy>\n" +
                        "                        </sp:TransportToken>\n" +
                        "                        <sp:AlgorithmSuite>\n" +
                        "                            <wsp:Policy>\n" +
                        "                                <sp:Basic256/>\n" +
                        "                            </wsp:Policy>\n" +
                        "                        </sp:AlgorithmSuite>\n" +
                        "                        <sp:Layout>\n" +
                        "                            <wsp:Policy>\n" +
                        "                                <sp:Lax/>\n" +
                        "                            </wsp:Policy>\n" +
                        "                        </sp:Layout>\n" +
                        "                        <sp:IncludeTimestamp/>\n" +
                        "                    </wsp:Policy>\n" +
                        "                </sp:TransportBinding>\n" +
                        "                <sp:SignedParts>\n" +
                        "                    <sp:Body/>\n" +
                        "                    <sp:Header Name=\"Header1\" Namespace=\"...\"/>\n" +
                        "                    <sp:Header Namespace=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\"/>\n" +
                        "                </sp:SignedParts>\n" +
                        "                <sp:SignedElements>\n" +
                        "                    <sp:XPath xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">wsu:Created</sp:XPath>\n" +
                        "                </sp:SignedElements>\n" +
                        "                <sp:EncryptedParts>\n" +
                        "                    <sp:Body/>\n" +
                        "                    <sp:Header Name=\"Header2\" Namespace=\"...\"/>\n" +
                        "                    <sp:Header Namespace=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\"/>\n" +
                        "                </sp:EncryptedParts>\n" +
                        "                <sp:EncryptedElements>\n" +
                        "                    <sp:XPath xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">wsu:Created</sp:XPath>\n" +
                        "                </sp:EncryptedElements>\n" +
                        "                <sp:ContentEncryptedElements>\n" +
                        "                    <sp:XPath xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">wsu:Expires</sp:XPath>\n" +
                        "                </sp:ContentEncryptedElements>\n" +
                        "            </wsp:All>\n" +
                        "        </wsp:ExactlyOne>";

        WSSSecurityProperties outSecurityProperties = new WSSSecurityProperties();
        outSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
        outSecurityProperties.setEncryptionUser("receiver");
        outSecurityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
        outSecurityProperties.setSignatureUser("transmitter");
        outSecurityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());

        List<WSSConstants.Action> actions = new ArrayList<>();
        actions.add(WSSConstants.TIMESTAMP);
        actions.add(WSSConstants.SIGNATURE);
        actions.add(WSSConstants.ENCRYPTION);
        outSecurityProperties.setActions(actions);

        InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
        ByteArrayOutputStream baos = doOutboundSecurity(outSecurityProperties, sourceDocument);

        WSSSecurityProperties inSecurityProperties = new WSSSecurityProperties();
        inSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
        inSecurityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
        inSecurityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());

        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);
        inSecurityProperties.addInputProcessor(new PolicyInputProcessor(policyEnforcer, null));

        HttpsTokenSecurityEvent httpsTokenSecurityEvent = new HttpsTokenSecurityEvent();
        httpsTokenSecurityEvent.setIssuerName("transmitter");
        httpsTokenSecurityEvent.setAuthenticationType(HttpsTokenSecurityEvent.AuthenticationType.HttpBasicAuthentication);
        HttpsSecurityTokenImpl httpsSecurityToken = new HttpsSecurityTokenImpl(true, "transmitter");
        httpsSecurityToken.addTokenUsage(WSSecurityTokenConstants.TOKENUSAGE_MAIN_SIGNATURE);
        httpsTokenSecurityEvent.setSecurityToken(httpsSecurityToken);

        List<SecurityEvent> securityEventList = new ArrayList<>();
        securityEventList.add(httpsTokenSecurityEvent);

        Document document = doInboundSecurity(inSecurityProperties, new ByteArrayInputStream(baos.toByteArray()), securityEventList, policyEnforcer);

        //read the whole stream:
        Transformer transformer = TransformerFactory.newInstance().newTransformer();
        transformer.transform(new DOMSource(document), new StreamResult(
                new OutputStream() {
                    @Override
                    public void write(int b) throws IOException {
                        // > /dev/null
                    }
                }
        ));
    }

    @Test
    public void testIncludeTimestampPolicyNegativeTest() throws Exception {

        String policyString =
                "<wsp:ExactlyOne xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\" " +
                        "xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\">\n" +
                        "            <wsp:All>\n" +
                        "                <sp:TransportBinding>\n" +
                        "                    <wsp:Policy>\n" +
                        "                        <sp:TransportToken>\n" +
                        "                            <wsp:Policy>\n" +
                        "                                <sp:HttpsToken>\n" +
                        "                                    <!--<sp:Issuer>wsa:EndpointReferenceType</sp:Issuer>-->\n" +
                        "                                    <sp:IssuerName>transmitter</sp:IssuerName>\n" +
                        "                                    <wsp:Policy>\n" +
                        "                                        <sp:HttpBasicAuthentication/>\n" +
                        "                                    </wsp:Policy>\n" +
                        "                                </sp:HttpsToken>\n" +
                        "                            </wsp:Policy>\n" +
                        "                        </sp:TransportToken>\n" +
                        "                        <sp:AlgorithmSuite>\n" +
                        "                            <wsp:Policy>\n" +
                        "                                <sp:Basic256/>\n" +
                        "                            </wsp:Policy>\n" +
                        "                        </sp:AlgorithmSuite>\n" +
                        "                        <sp:Layout>\n" +
                        "                            <wsp:Policy>\n" +
                        "                                <sp:Lax/>\n" +
                        "                            </wsp:Policy>\n" +
                        "                        </sp:Layout>\n" +
                        "                        <sp:IncludeTimestamp/>\n" +
                        "                    </wsp:Policy>\n" +
                        "                </sp:TransportBinding>\n" +
                        "                <sp:SignedParts>\n" +
                        "                    <sp:Body/>\n" +
                        "                    <sp:Header Name=\"Header1\" Namespace=\"...\"/>\n" +
                        "                    <sp:Header Namespace=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\"/>\n" +
                        "                </sp:SignedParts>\n" +
                        "                <sp:SignedElements>\n" +
                        "                    <sp:XPath xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">wsu:Created</sp:XPath>\n" +
                        "                </sp:SignedElements>\n" +
                        "                <sp:EncryptedParts>\n" +
                        "                    <sp:Body/>\n" +
                        "                    <sp:Header Name=\"Header2\" Namespace=\"...\"/>\n" +
                        "                    <sp:Header Namespace=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\"/>\n" +
                        "                </sp:EncryptedParts>\n" +
                        "                <sp:EncryptedElements>\n" +
                        "                    <sp:XPath xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">wsu:Created</sp:XPath>\n" +
                        "                </sp:EncryptedElements>\n" +
                        "                <sp:ContentEncryptedElements>\n" +
                        "                    <sp:XPath xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">wsu:Expires</sp:XPath>\n" +
                        "                </sp:ContentEncryptedElements>\n" +
                        "            </wsp:All>\n" +
                        "        </wsp:ExactlyOne>";

        WSSSecurityProperties outSecurityProperties = new WSSSecurityProperties();
        outSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
        outSecurityProperties.setEncryptionUser("receiver");
        outSecurityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
        outSecurityProperties.setSignatureUser("transmitter");
        outSecurityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());

        List<WSSConstants.Action> actions = new ArrayList<>();
        actions.add(WSSConstants.SIGNATURE);
        actions.add(WSSConstants.ENCRYPTION);
        outSecurityProperties.setActions(actions);

        InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
        ByteArrayOutputStream baos = doOutboundSecurity(outSecurityProperties, sourceDocument);

        WSSSecurityProperties inSecurityProperties = new WSSSecurityProperties();
        inSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
        inSecurityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
        inSecurityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());

        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);
        inSecurityProperties.addInputProcessor(new PolicyInputProcessor(policyEnforcer, null));

        HttpsTokenSecurityEvent httpsTokenSecurityEvent = new HttpsTokenSecurityEvent();
        httpsTokenSecurityEvent.setIssuerName("transmitter");
        httpsTokenSecurityEvent.setAuthenticationType(HttpsTokenSecurityEvent.AuthenticationType.HttpBasicAuthentication);
        HttpsSecurityTokenImpl httpsSecurityToken = new HttpsSecurityTokenImpl(true, "transmitter");
        httpsSecurityToken.addTokenUsage(WSSecurityTokenConstants.TOKENUSAGE_MAIN_SIGNATURE);
        httpsTokenSecurityEvent.setSecurityToken(httpsSecurityToken);

        List<SecurityEvent> securityEventList = new ArrayList<>();
        securityEventList.add(httpsTokenSecurityEvent);

        try {
            Document document = doInboundSecurity(inSecurityProperties, new ByteArrayInputStream(baos.toByteArray()), securityEventList, policyEnforcer);

            //read the whole stream:
            Transformer transformer = TransformerFactory.newInstance().newTransformer();
            transformer.transform(new DOMSource(document), new StreamResult(
                    new OutputStream() {
                        @Override
                        public void write(int b) throws IOException {
                            // > /dev/null
                        }
                    }
            ));
            fail("Exception expected");
        } catch (XMLStreamException e) {
            assertTrue(e.getCause() instanceof WSSecurityException);
            assertEquals(e.getCause().getMessage(),
                    "Element /{http://schemas.xmlsoap.org/soap/envelope/}Envelope/{http://schemas.xmlsoap.org/soap/envelope/}Header/{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd}Security/{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd}Timestamp must be present");
            assertEquals(((WSSecurityException) e.getCause()).getFaultCode(), WSSecurityException.INVALID_SECURITY);
        }
    }

    @Test
    public void testIncludeTimestampAndSignedUsernameSupportingTokenPolicy() throws Exception {

        String policyString =
                "<wsp:ExactlyOne xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\" " +
                        "xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\">\n" +
                        "            <wsp:All>\n" +
                        "                <sp:TransportBinding>\n" +
                        "                    <wsp:Policy>\n" +
                        "                        <sp:TransportToken>\n" +
                        "                            <wsp:Policy>\n" +
                        "                                <sp:HttpsToken>\n" +
                        "                                    <!--<sp:Issuer>wsa:EndpointReferenceType</sp:Issuer>-->\n" +
                        "                                    <sp:IssuerName>transmitter</sp:IssuerName>\n" +
                        "                                    <wsp:Policy>\n" +
                        "                                        <sp:HttpBasicAuthentication/>\n" +
                        "                                    </wsp:Policy>\n" +
                        "                                </sp:HttpsToken>\n" +
                        "                            </wsp:Policy>\n" +
                        "                        </sp:TransportToken>\n" +
                        "                        <sp:AlgorithmSuite>\n" +
                        "                            <wsp:Policy>\n" +
                        "                                <sp:Basic256/>\n" +
                        "                            </wsp:Policy>\n" +
                        "                        </sp:AlgorithmSuite>\n" +
                        "                        <sp:Layout>\n" +
                        "                            <wsp:Policy>\n" +
                        "                                <sp:Lax/>\n" +
                        "                            </wsp:Policy>\n" +
                        "                        </sp:Layout>\n" +
                        "                        <sp:IncludeTimestamp/>\n" +
                        "                    </wsp:Policy>\n" +
                        "                </sp:TransportBinding>\n" +
                        "                <sp:SignedParts>\n" +
                        "                    <sp:Body/>\n" +
                        "                    <sp:Header Name=\"Header1\" Namespace=\"...\"/>\n" +
                        "                    <sp:Header Namespace=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\"/>\n" +
                        "                </sp:SignedParts>\n" +
                        "                <sp:SignedElements>\n" +
                        "                    <sp:XPath xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">wsu:Created</sp:XPath>\n" +
                        "                </sp:SignedElements>\n" +
                        "                <sp:EncryptedParts>\n" +
                        "                    <sp:Body/>\n" +
                        "                    <sp:Header Name=\"Header2\" Namespace=\"...\"/>\n" +
                        "                    <sp:Header Namespace=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\"/>\n" +
                        "                </sp:EncryptedParts>\n" +
                        "                <sp:EncryptedElements>\n" +
                        "                    <sp:XPath xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">wsu:Created</sp:XPath>\n" +
                        "                </sp:EncryptedElements>\n" +
                        "                <sp:ContentEncryptedElements>\n" +
                        "                    <sp:XPath xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">wsu:Expires</sp:XPath>\n" +
                        "                </sp:ContentEncryptedElements>\n" +
                        "                <sp:SignedSupportingTokens>\n" +
                        "                    <wsp:Policy>\n" +
                        "                        <sp:UsernameToken sp:IncludeToken=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702/IncludeToken/AlwaysToRecipient\">\n" +
                        "                            <wsp:Policy>\n" +
                        "                                <sp:NoPassword/>\n" +
                        "                            </wsp:Policy>\n" +
                        "                        </sp:UsernameToken>\n" +
                        "                    </wsp:Policy>\n" +
                        "                </sp:SignedSupportingTokens>\n" +
                        "            </wsp:All>\n" +
                        "        </wsp:ExactlyOne>";

        WSSSecurityProperties outSecurityProperties = new WSSSecurityProperties();
        outSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
        outSecurityProperties.setEncryptionUser("receiver");
        outSecurityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
        outSecurityProperties.setSignatureUser("transmitter");
        outSecurityProperties.setTokenUser("transmitter");
        outSecurityProperties.setUsernameTokenPasswordType(WSSConstants.UsernameTokenPasswordType.PASSWORD_NONE);
        outSecurityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());

        List<WSSConstants.Action> actions = new ArrayList<>();
        actions.add(WSSConstants.USERNAMETOKEN);
        actions.add(WSSConstants.TIMESTAMP);
        actions.add(WSSConstants.SIGNATURE);
        actions.add(WSSConstants.ENCRYPTION);
        outSecurityProperties.setActions(actions);

        InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
        ByteArrayOutputStream baos = doOutboundSecurity(outSecurityProperties, sourceDocument);

        WSSSecurityProperties inSecurityProperties = new WSSSecurityProperties();
        inSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
        inSecurityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
        inSecurityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());

        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);
        inSecurityProperties.addInputProcessor(new PolicyInputProcessor(policyEnforcer, null));

        HttpsTokenSecurityEvent httpsTokenSecurityEvent = new HttpsTokenSecurityEvent();
        httpsTokenSecurityEvent.setIssuerName("transmitter");
        httpsTokenSecurityEvent.setAuthenticationType(HttpsTokenSecurityEvent.AuthenticationType.HttpBasicAuthentication);
        HttpsSecurityTokenImpl httpsSecurityToken = new HttpsSecurityTokenImpl(true, "transmitter");
        httpsSecurityToken.addTokenUsage(WSSecurityTokenConstants.TOKENUSAGE_MAIN_SIGNATURE);
        httpsTokenSecurityEvent.setSecurityToken(httpsSecurityToken);

        List<SecurityEvent> securityEventList = new ArrayList<>();
        securityEventList.add(httpsTokenSecurityEvent);

        Document document = doInboundSecurity(inSecurityProperties, new ByteArrayInputStream(baos.toByteArray()), securityEventList, policyEnforcer);

        //read the whole stream:
        Transformer transformer = TransformerFactory.newInstance().newTransformer();
        transformer.transform(new DOMSource(document), new StreamResult(
                new OutputStream() {
                    @Override
                    public void write(int b) throws IOException {
                        // > /dev/null
                    }
                }
        ));
    }

    @Test
    public void testIncludeTimestampAndSignedUsernameSupportingTokenPolicyNegativeTest() throws Exception {

        String policyString =
                "<wsp:ExactlyOne xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\" " +
                        "xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\">\n" +
                        "            <wsp:All>\n" +
                        "                <sp:TransportBinding>\n" +
                        "                    <wsp:Policy>\n" +
                        "                        <sp:TransportToken>\n" +
                        "                            <wsp:Policy>\n" +
                        "                                <sp:HttpsToken>\n" +
                        "                                    <!--<sp:Issuer>wsa:EndpointReferenceType</sp:Issuer>-->\n" +
                        "                                    <sp:IssuerName>transmitter</sp:IssuerName>\n" +
                        "                                    <wsp:Policy>\n" +
                        "                                        <sp:HttpBasicAuthentication/>\n" +
                        "                                    </wsp:Policy>\n" +
                        "                                </sp:HttpsToken>\n" +
                        "                            </wsp:Policy>\n" +
                        "                        </sp:TransportToken>\n" +
                        "                        <sp:AlgorithmSuite>\n" +
                        "                            <wsp:Policy>\n" +
                        "                                <sp:Basic256/>\n" +
                        "                            </wsp:Policy>\n" +
                        "                        </sp:AlgorithmSuite>\n" +
                        "                        <sp:Layout>\n" +
                        "                            <wsp:Policy>\n" +
                        "                                <sp:Lax/>\n" +
                        "                            </wsp:Policy>\n" +
                        "                        </sp:Layout>\n" +
                        "                        <sp:IncludeTimestamp/>\n" +
                        "                    </wsp:Policy>\n" +
                        "                </sp:TransportBinding>\n" +
                        "                <sp:SignedParts>\n" +
                        "                    <sp:Body/>\n" +
                        "                    <sp:Header Name=\"Header1\" Namespace=\"...\"/>\n" +
                        "                    <sp:Header Namespace=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\"/>\n" +
                        "                </sp:SignedParts>\n" +
                        "                <sp:SignedElements>\n" +
                        "                    <sp:XPath xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">wsu:Created</sp:XPath>\n" +
                        "                </sp:SignedElements>\n" +
                        "                <sp:EncryptedParts>\n" +
                        "                    <sp:Body/>\n" +
                        "                    <sp:Header Name=\"Header2\" Namespace=\"...\"/>\n" +
                        "                    <sp:Header Namespace=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\"/>\n" +
                        "                </sp:EncryptedParts>\n" +
                        "                <sp:EncryptedElements>\n" +
                        "                    <sp:XPath xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">wsu:Created</sp:XPath>\n" +
                        "                </sp:EncryptedElements>\n" +
                        "                <sp:ContentEncryptedElements>\n" +
                        "                    <sp:XPath xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">wsu:Expires</sp:XPath>\n" +
                        "                </sp:ContentEncryptedElements>\n" +
                        "                <sp:SignedSupportingTokens>\n" +
                        "                    <wsp:Policy>\n" +
                        "                        <sp:UsernameToken sp:IncludeToken=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702/IncludeToken/AlwaysToRecipient\">\n" +
                        "                            <wsp:Policy>\n" +
                        "                                <sp:NoPassword/>\n" +
                        "                            </wsp:Policy>\n" +
                        "                        </sp:UsernameToken>\n" +
                        "                    </wsp:Policy>\n" +
                        "                </sp:SignedSupportingTokens>\n" +
                        "            </wsp:All>\n" +
                        "        </wsp:ExactlyOne>";

        WSSSecurityProperties outSecurityProperties = new WSSSecurityProperties();
        outSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
        outSecurityProperties.setEncryptionUser("receiver");
        outSecurityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
        outSecurityProperties.setSignatureUser("transmitter");
        outSecurityProperties.setTokenUser("transmitter");
        outSecurityProperties.setUsernameTokenPasswordType(WSSConstants.UsernameTokenPasswordType.PASSWORD_NONE);
        outSecurityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());

        List<WSSConstants.Action> actions = new ArrayList<>();
        actions.add(WSSConstants.TIMESTAMP);
        actions.add(WSSConstants.SIGNATURE);
        actions.add(WSSConstants.ENCRYPTION);
        outSecurityProperties.setActions(actions);

        InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
        ByteArrayOutputStream baos = doOutboundSecurity(outSecurityProperties, sourceDocument);

        WSSSecurityProperties inSecurityProperties = new WSSSecurityProperties();
        inSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
        inSecurityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
        inSecurityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());

        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);
        inSecurityProperties.addInputProcessor(new PolicyInputProcessor(policyEnforcer, null));

        HttpsTokenSecurityEvent httpsTokenSecurityEvent = new HttpsTokenSecurityEvent();
        httpsTokenSecurityEvent.setIssuerName("transmitter");
        httpsTokenSecurityEvent.setAuthenticationType(HttpsTokenSecurityEvent.AuthenticationType.HttpBasicAuthentication);
        HttpsSecurityTokenImpl httpsSecurityToken = new HttpsSecurityTokenImpl(true, "transmitter");
        httpsSecurityToken.addTokenUsage(WSSecurityTokenConstants.TOKENUSAGE_MAIN_SIGNATURE);
        httpsTokenSecurityEvent.setSecurityToken(httpsSecurityToken);

        List<SecurityEvent> securityEventList = new ArrayList<>();
        securityEventList.add(httpsTokenSecurityEvent);

        try {
            Document document = doInboundSecurity(inSecurityProperties, new ByteArrayInputStream(baos.toByteArray()), securityEventList, policyEnforcer);

            //read the whole stream:
            Transformer transformer = TransformerFactory.newInstance().newTransformer();
            transformer.transform(new DOMSource(document), new StreamResult(
                    new OutputStream() {
                        @Override
                        public void write(int b) throws IOException {
                            // > /dev/null
                        }
                    }
            ));
            fail("Exception expected");
        } catch (XMLStreamException e) {
            assertTrue(e.getCause() instanceof WSSecurityException);
            assertEquals(e.getCause().getMessage(),
                    "Assertion {http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702}UsernameToken not satisfied");
            assertEquals(((WSSecurityException) e.getCause()).getFaultCode(), WSSecurityException.INVALID_SECURITY);
        }
    }

    @Test
    public void testIncludeTimestampAndSignedUsernameSupportingTokenPolicyNegativeTest_2() throws Exception {

        String policyString =
                "<wsp:ExactlyOne xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\" " +
                        "xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\">\n" +
                        "            <wsp:All>\n" +
                        "                <sp:TransportBinding>\n" +
                        "                    <wsp:Policy>\n" +
                        "                        <sp:TransportToken>\n" +
                        "                            <wsp:Policy>\n" +
                        "                                <sp:HttpsToken>\n" +
                        "                                    <!--<sp:Issuer>wsa:EndpointReferenceType</sp:Issuer>-->\n" +
                        "                                    <sp:IssuerName>transmitter</sp:IssuerName>\n" +
                        "                                    <wsp:Policy>\n" +
                        "                                        <sp:HttpBasicAuthentication/>\n" +
                        "                                    </wsp:Policy>\n" +
                        "                                </sp:HttpsToken>\n" +
                        "                            </wsp:Policy>\n" +
                        "                        </sp:TransportToken>\n" +
                        "                        <sp:AlgorithmSuite>\n" +
                        "                            <wsp:Policy>\n" +
                        "                                <sp:Basic256/>\n" +
                        "                            </wsp:Policy>\n" +
                        "                        </sp:AlgorithmSuite>\n" +
                        "                        <sp:Layout>\n" +
                        "                            <wsp:Policy>\n" +
                        "                                <sp:Lax/>\n" +
                        "                            </wsp:Policy>\n" +
                        "                        </sp:Layout>\n" +
                        "                    </wsp:Policy>\n" +
                        "                </sp:TransportBinding>\n" +
                        "                <sp:SignedSupportingTokens>\n" +
                        "                    <wsp:Policy>\n" +
                        "                        <sp:UsernameToken sp:IncludeToken=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702/IncludeToken/AlwaysToRecipient\">\n" +
                        "                            <wsp:Policy>\n" +
                        "                                <sp:NoPassword/>\n" +
                        "                            </wsp:Policy>\n" +
                        "                        </sp:UsernameToken>\n" +
                        "                    </wsp:Policy>\n" +
                        "                </sp:SignedSupportingTokens>\n" +
                        "            </wsp:All>\n" +
                        "        </wsp:ExactlyOne>";

        WSSSecurityProperties outSecurityProperties = new WSSSecurityProperties();
        outSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
        outSecurityProperties.setEncryptionUser("receiver");
        outSecurityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
        outSecurityProperties.setSignatureUser("transmitter");
        outSecurityProperties.setTokenUser("transmitter");
        outSecurityProperties.setUsernameTokenPasswordType(WSSConstants.UsernameTokenPasswordType.PASSWORD_NONE);
        outSecurityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());

        List<WSSConstants.Action> actions = new ArrayList<>();
        actions.add(WSSConstants.SIGNATURE);
        actions.add(WSSConstants.ENCRYPTION);
        outSecurityProperties.setActions(actions);

        InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
        ByteArrayOutputStream baos = doOutboundSecurity(outSecurityProperties, sourceDocument);

        WSSSecurityProperties inSecurityProperties = new WSSSecurityProperties();
        inSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
        inSecurityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
        inSecurityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());

        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);
        inSecurityProperties.addInputProcessor(new PolicyInputProcessor(policyEnforcer, inSecurityProperties));

        HttpsTokenSecurityEvent httpsTokenSecurityEvent = new HttpsTokenSecurityEvent();
        httpsTokenSecurityEvent.setIssuerName("transmitter");
        httpsTokenSecurityEvent.setAuthenticationType(HttpsTokenSecurityEvent.AuthenticationType.HttpBasicAuthentication);
        HttpsSecurityTokenImpl httpsSecurityToken = new HttpsSecurityTokenImpl(true, "transmitter");
        httpsSecurityToken.addTokenUsage(WSSecurityTokenConstants.TOKENUSAGE_MAIN_SIGNATURE);
        httpsTokenSecurityEvent.setSecurityToken(httpsSecurityToken);

        List<SecurityEvent> securityEventList = new ArrayList<>();
        securityEventList.add(httpsTokenSecurityEvent);

        try {
            Document document = doInboundSecurity(inSecurityProperties, new ByteArrayInputStream(baos.toByteArray()), securityEventList, policyEnforcer);

            //read the whole stream:
            Transformer transformer = TransformerFactory.newInstance().newTransformer();
            transformer.transform(new DOMSource(document), new StreamResult(
                    new OutputStream() {
                        @Override
                        public void write(int b) throws IOException {
                            // > /dev/null
                        }
                    }
            ));
            fail("Exception expected");
        } catch (XMLStreamException e) {
            assertTrue(e.getCause() instanceof WSSecurityException);
            assertEquals(e.getCause().getMessage(),
                    "Assertion {http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702}UsernameToken not satisfied");
            assertEquals(((WSSecurityException) e.getCause()).getFaultCode(), WSSecurityException.INVALID_SECURITY);
        }
    }

    @Test
    public void testIncludeTimestampAndSignedEncryptedUsernameSupportingTokenPolicy() throws Exception {

        String policyString =
                "<wsp:ExactlyOne xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\" " +
                        "xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\">\n" +
                        "            <wsp:All>\n" +
                        "                <sp:TransportBinding>\n" +
                        "                    <wsp:Policy>\n" +
                        "                        <sp:TransportToken>\n" +
                        "                            <wsp:Policy>\n" +
                        "                                <sp:HttpsToken>\n" +
                        "                                    <!--<sp:Issuer>wsa:EndpointReferenceType</sp:Issuer>-->\n" +
                        "                                    <sp:IssuerName>transmitter</sp:IssuerName>\n" +
                        "                                    <wsp:Policy>\n" +
                        "                                        <sp:HttpBasicAuthentication/>\n" +
                        "                                    </wsp:Policy>\n" +
                        "                                </sp:HttpsToken>\n" +
                        "                            </wsp:Policy>\n" +
                        "                        </sp:TransportToken>\n" +
                        "                        <sp:AlgorithmSuite>\n" +
                        "                            <wsp:Policy>\n" +
                        "                                <sp:Basic256/>\n" +
                        "                            </wsp:Policy>\n" +
                        "                        </sp:AlgorithmSuite>\n" +
                        "                        <sp:Layout>\n" +
                        "                            <wsp:Policy>\n" +
                        "                                <sp:Lax/>\n" +
                        "                            </wsp:Policy>\n" +
                        "                        </sp:Layout>\n" +
                        "                        <sp:IncludeTimestamp/>\n" +
                        "                    </wsp:Policy>\n" +
                        "                </sp:TransportBinding>\n" +
                        "                <sp:SignedParts>\n" +
                        "                    <sp:Body/>\n" +
                        "                    <sp:Header Name=\"Header1\" Namespace=\"...\"/>\n" +
                        "                    <sp:Header Namespace=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\"/>\n" +
                        "                </sp:SignedParts>\n" +
                        "                <sp:SignedElements>\n" +
                        "                    <sp:XPath xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">wsu:Created</sp:XPath>\n" +
                        "                </sp:SignedElements>\n" +
                        "                <sp:EncryptedParts>\n" +
                        "                    <sp:Body/>\n" +
                        "                    <sp:Header Name=\"Header2\" Namespace=\"...\"/>\n" +
                        "                    <sp:Header Namespace=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\"/>\n" +
                        "                </sp:EncryptedParts>\n" +
                        "                <sp:EncryptedElements>\n" +
                        "                    <sp:XPath xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">wsu:Created</sp:XPath>\n" +
                        "                </sp:EncryptedElements>\n" +
                        "                <sp:ContentEncryptedElements>\n" +
                        "                    <sp:XPath xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">wsu:Expires</sp:XPath>\n" +
                        "                </sp:ContentEncryptedElements>\n" +
                        "                <sp:SignedEncryptedSupportingTokens>\n" +
                        "                    <wsp:Policy>\n" +
                        "                        <sp:UsernameToken sp:IncludeToken=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702/IncludeToken/AlwaysToRecipient\">\n" +
                        "                            <wsp:Policy>\n" +
                        "                                <sp:NoPassword/>\n" +
                        "                            </wsp:Policy>\n" +
                        "                        </sp:UsernameToken>\n" +
                        "                    </wsp:Policy>\n" +
                        "                </sp:SignedEncryptedSupportingTokens>\n" +
                        "            </wsp:All>\n" +
                        "        </wsp:ExactlyOne>";

        WSSSecurityProperties outSecurityProperties = new WSSSecurityProperties();
        outSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
        outSecurityProperties.setEncryptionUser("receiver");
        outSecurityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
        outSecurityProperties.setSignatureUser("transmitter");
        outSecurityProperties.setTokenUser("transmitter");
        outSecurityProperties.setUsernameTokenPasswordType(WSSConstants.UsernameTokenPasswordType.PASSWORD_NONE);
        outSecurityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());

        List<WSSConstants.Action> actions = new ArrayList<>();
        actions.add(WSSConstants.USERNAMETOKEN);
        actions.add(WSSConstants.TIMESTAMP);
        actions.add(WSSConstants.SIGNATURE);
        actions.add(WSSConstants.ENCRYPTION);
        outSecurityProperties.setActions(actions);

        InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
        ByteArrayOutputStream baos = doOutboundSecurity(outSecurityProperties, sourceDocument);

        WSSSecurityProperties inSecurityProperties = new WSSSecurityProperties();
        inSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
        inSecurityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
        inSecurityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());

        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);
        inSecurityProperties.addInputProcessor(new PolicyInputProcessor(policyEnforcer, null));

        HttpsTokenSecurityEvent httpsTokenSecurityEvent = new HttpsTokenSecurityEvent();
        httpsTokenSecurityEvent.setIssuerName("transmitter");
        httpsTokenSecurityEvent.setAuthenticationType(HttpsTokenSecurityEvent.AuthenticationType.HttpBasicAuthentication);
        HttpsSecurityTokenImpl httpsSecurityToken = new HttpsSecurityTokenImpl(true, "transmitter");
        httpsSecurityToken.addTokenUsage(WSSecurityTokenConstants.TOKENUSAGE_MAIN_SIGNATURE);
        httpsTokenSecurityEvent.setSecurityToken(httpsSecurityToken);

        List<SecurityEvent> securityEventList = new ArrayList<>();
        securityEventList.add(httpsTokenSecurityEvent);

        Document document = doInboundSecurity(inSecurityProperties, new ByteArrayInputStream(baos.toByteArray()), securityEventList, policyEnforcer);

        //read the whole stream:
        Transformer transformer = TransformerFactory.newInstance().newTransformer();
        transformer.transform(new DOMSource(document), new StreamResult(
                new OutputStream() {
                    @Override
                    public void write(int b) throws IOException {
                        // > /dev/null
                    }
                }
        ));
    }

    @Test
    public void testIncludeTimestampAndProtectionOrderEncryptBeforeSignAndSignedUsernameSupportingTokenPolicyTest() throws Exception {

        String policyString =
                "<wsp:ExactlyOne xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\" " +
                        "xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\">\n" +
                        "            <wsp:All>\n" +
                        "                <sp:TransportBinding>\n" +
                        "                    <wsp:Policy>\n" +
                        "                        <sp:TransportToken>\n" +
                        "                            <wsp:Policy>\n" +
                        "                                <sp:HttpsToken>\n" +
                        "                                    <!--<sp:Issuer>wsa:EndpointReferenceType</sp:Issuer>-->\n" +
                        "                                    <sp:IssuerName>transmitter</sp:IssuerName>\n" +
                        "                                    <wsp:Policy>\n" +
                        "                                        <sp:HttpBasicAuthentication/>\n" +
                        "                                    </wsp:Policy>\n" +
                        "                                </sp:HttpsToken>\n" +
                        "                            </wsp:Policy>\n" +
                        "                        </sp:TransportToken>\n" +
                        "                        <sp:AlgorithmSuite>\n" +
                        "                            <wsp:Policy>\n" +
                        "                                <sp:Basic256/>\n" +
                        "                            </wsp:Policy>\n" +
                        "                        </sp:AlgorithmSuite>\n" +
                        "                        <sp:Layout>\n" +
                        "                            <wsp:Policy>\n" +
                        "                                <sp:Lax/>\n" +
                        "                            </wsp:Policy>\n" +
                        "                        </sp:Layout>\n" +
                        "                        <sp:IncludeTimestamp/>\n" +
                        "                    </wsp:Policy>\n" +
                        "                </sp:TransportBinding>\n" +
                        "                <sp:SignedParts>\n" +
                        "                    <sp:Body/>\n" +
                        "                    <sp:Header Name=\"Header1\" Namespace=\"...\"/>\n" +
                        "                    <sp:Header Namespace=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\"/>\n" +
                        "                </sp:SignedParts>\n" +
                        "                <sp:SignedElements>\n" +
                        "                    <sp:XPath xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">wsu:Created</sp:XPath>\n" +
                        "                </sp:SignedElements>\n" +
                        "                <sp:EncryptedParts>\n" +
                        "                    <sp:Body/>\n" +
                        "                </sp:EncryptedParts>\n" +
                        "                <sp:SignedSupportingTokens>\n" +
                        "                    <wsp:Policy>\n" +
                        "                        <sp:UsernameToken sp:IncludeToken=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702/IncludeToken/AlwaysToRecipient\">\n" +
                        "                            <wsp:Policy>\n" +
                        "                                <sp:NoPassword/>\n" +
                        "                            </wsp:Policy>\n" +
                        "                        </sp:UsernameToken>\n" +
                        "                    </wsp:Policy>\n" +
                        "                </sp:SignedSupportingTokens>\n" +
                        "            </wsp:All>\n" +
                        "        </wsp:ExactlyOne>";

        WSSSecurityProperties outSecurityProperties = new WSSSecurityProperties();
        outSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
        outSecurityProperties.setEncryptionUser("receiver");
        outSecurityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
        outSecurityProperties.setSignatureUser("transmitter");
        outSecurityProperties.setTokenUser("transmitter");
        outSecurityProperties.setUsernameTokenPasswordType(WSSConstants.UsernameTokenPasswordType.PASSWORD_NONE);
        outSecurityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());

        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_SOAP11_BODY, SecurePart.Modifier.Content));
        List<WSSConstants.Action> actions = new ArrayList<>();
        actions.add(WSSConstants.USERNAMETOKEN);
        actions.add(WSSConstants.TIMESTAMP);
        actions.add(WSSConstants.ENCRYPTION);
        outSecurityProperties.setActions(actions);

        InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
        ByteArrayOutputStream baos = doOutboundSecurity(outSecurityProperties, sourceDocument);

        WSSSecurityProperties inSecurityProperties = new WSSSecurityProperties();
        inSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
        inSecurityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
        inSecurityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());

        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);
        inSecurityProperties.addInputProcessor(new PolicyInputProcessor(policyEnforcer, null));

        HttpsTokenSecurityEvent httpsTokenSecurityEvent = new HttpsTokenSecurityEvent();
        httpsTokenSecurityEvent.setIssuerName("transmitter");
        httpsTokenSecurityEvent.setAuthenticationType(HttpsTokenSecurityEvent.AuthenticationType.HttpBasicAuthentication);
        HttpsSecurityTokenImpl httpsSecurityToken = new HttpsSecurityTokenImpl(true, "transmitter");
        //todo token usage hard-coded in httpsSecurityToken?
        httpsSecurityToken.addTokenUsage(WSSecurityTokenConstants.TOKENUSAGE_MAIN_SIGNATURE);
        httpsTokenSecurityEvent.setSecurityToken(httpsSecurityToken);

        List<SecurityEvent> securityEventList = new ArrayList<>();
        securityEventList.add(httpsTokenSecurityEvent);

        Document document = doInboundSecurity(inSecurityProperties, new ByteArrayInputStream(baos.toByteArray()), securityEventList, policyEnforcer);

        //read the whole stream:
        Transformer transformer = TransformerFactory.newInstance().newTransformer();
        transformer.transform(new DOMSource(document), new StreamResult(
                new OutputStream() {
                    @Override
                    public void write(int b) throws IOException {
                        // > /dev/null
                    }
                }
        ));
    }

    @Test
    public void testHttpsClientAuthenticationIncludeTimestampAndSignedUsernameSupportingTokenPolicy() throws Exception {

        String policyString =
                "<wsp:ExactlyOne xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\" " +
                        "xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\">\n" +
                        "            <wsp:All>\n" +
                        "                <sp:TransportBinding>\n" +
                        "                    <wsp:Policy>\n" +
                        "                        <sp:TransportToken>\n" +
                        "                            <wsp:Policy>\n" +
                        "                                <sp:HttpsToken>\n" +
                        "                                    <!--<sp:Issuer>wsa:EndpointReferenceType</sp:Issuer>-->\n" +
                        "                                    <sp:IssuerName>CN=transmitter,OU=swssf,C=CH</sp:IssuerName>\n" +
                        "                                    <wsp:Policy>\n" +
                        "                                        <sp:RequireClientCertificate/>\n" +
                        "                                    </wsp:Policy>\n" +
                        "                                </sp:HttpsToken>\n" +
                        "                            </wsp:Policy>\n" +
                        "                        </sp:TransportToken>\n" +
                        "                        <sp:AlgorithmSuite>\n" +
                        "                            <wsp:Policy>\n" +
                        "                                <sp:Basic256/>\n" +
                        "                            </wsp:Policy>\n" +
                        "                        </sp:AlgorithmSuite>\n" +
                        "                        <sp:Layout>\n" +
                        "                            <wsp:Policy>\n" +
                        "                                <sp:Lax/>\n" +
                        "                            </wsp:Policy>\n" +
                        "                        </sp:Layout>\n" +
                        "                        <sp:IncludeTimestamp/>\n" +
                        "                    </wsp:Policy>\n" +
                        "                </sp:TransportBinding>\n" +
                        "                <sp:SignedParts>\n" +
                        "                    <sp:Body/>\n" +
                        "                    <sp:Header Name=\"Header1\" Namespace=\"...\"/>\n" +
                        "                    <sp:Header Namespace=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\"/>\n" +
                        "                </sp:SignedParts>\n" +
                        "                <sp:SignedElements>\n" +
                        "                    <sp:XPath xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\" " +
                        "                       xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\" " +
                        "                       xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">" +
                        "                       /soap:Envelope/soap:Header/wsse:Security/wsu:Timestamp/wsu:Created" +
                        "                    </sp:XPath>\n" +
                        "                </sp:SignedElements>\n" +
                        "                <sp:EncryptedParts>\n" +
                        "                    <sp:Body/>\n" +
                        "                    <sp:Header Name=\"Header2\" Namespace=\"...\"/>\n" +
                        "                    <sp:Header Namespace=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\"/>\n" +
                        "                </sp:EncryptedParts>\n" +
                        "                <sp:EncryptedElements>\n" +
                        "                    <sp:XPath xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\" " +
                        "                       xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\" " +
                        "                       xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">" +
                        "                       /soap:Envelope/soap:Header/wsse:Security/wsu:Timestamp/wsu:Created" +
                        "                    </sp:XPath>\n" +
                        "                </sp:EncryptedElements>\n" +
                        "                <sp:ContentEncryptedElements>\n" +
                        "                    <sp:XPath xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\" " +
                        "                       xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\" " +
                        "                       xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">" +
                        "                       /soap:Envelope/soap:Header/wsse:Security/wsu:Timestamp/wsu:Expires" +
                        "                    </sp:XPath>\n" +
                        "                </sp:ContentEncryptedElements>\n" +
                        "                <sp:SignedSupportingTokens>\n" +
                        "                    <wsp:Policy>\n" +
                        "                        <sp:UsernameToken sp:IncludeToken=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702/IncludeToken/AlwaysToRecipient\">\n" +
                        "                            <wsp:Policy>\n" +
                        "                                <!--<sp:HashPassword/>-->\n" +
                        "                                <sp:NoPassword/>\n" +
                        "                                <!--<sp:Created/>\n" +
                        "                                <sp:Nonce/>-->\n" +
                        "                            </wsp:Policy>\n" +
                        "                        </sp:UsernameToken>\n" +
                        "                    </wsp:Policy>\n" +
                        "                </sp:SignedSupportingTokens>\n" +
                        "            </wsp:All>\n" +
                        "        </wsp:ExactlyOne>";

        WSSSecurityProperties outSecurityProperties = new WSSSecurityProperties();
        outSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
        outSecurityProperties.setEncryptionUser("receiver");
        outSecurityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
        outSecurityProperties.setSignatureUser("transmitter");
        outSecurityProperties.setTokenUser("transmitter");
        outSecurityProperties.setUsernameTokenPasswordType(WSSConstants.UsernameTokenPasswordType.PASSWORD_NONE);
        outSecurityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());

        outSecurityProperties.addSignaturePart(new SecurePart(WSSConstants.TAG_SOAP11_BODY, SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_SOAP11_BODY, SecurePart.Modifier.Content));
        List<WSSConstants.Action> actions = new ArrayList<>();
        actions.add(WSSConstants.USERNAMETOKEN);
        actions.add(WSSConstants.TIMESTAMP);
        actions.add(WSSConstants.SIGNATURE);
        actions.add(WSSConstants.ENCRYPTION);
        outSecurityProperties.setActions(actions);

        InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
        ByteArrayOutputStream baos = doOutboundSecurity(outSecurityProperties, sourceDocument);

        WSSSecurityProperties inSecurityProperties = new WSSSecurityProperties();
        inSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
        inSecurityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
        inSecurityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());

        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);
        inSecurityProperties.addInputProcessor(new PolicyInputProcessor(policyEnforcer, null));

        HttpsTokenSecurityEvent httpsTokenSecurityEvent = new HttpsTokenSecurityEvent();
        httpsTokenSecurityEvent.setIssuerName("CN=transmitter,OU=swssf,C=CH");
        httpsTokenSecurityEvent.setAuthenticationType(HttpsTokenSecurityEvent.AuthenticationType.HttpsClientCertificateAuthentication);
        HttpsSecurityTokenImpl httpsSecurityToken = new HttpsSecurityTokenImpl(true, "CN=transmitter,OU=swssf,C=CH");
        httpsSecurityToken.addTokenUsage(WSSecurityTokenConstants.TOKENUSAGE_MAIN_SIGNATURE);
        httpsTokenSecurityEvent.setSecurityToken(httpsSecurityToken);

        List<SecurityEvent> securityEventList = new ArrayList<>();
        securityEventList.add(httpsTokenSecurityEvent);

        Document document = doInboundSecurity(inSecurityProperties, new ByteArrayInputStream(baos.toByteArray()), securityEventList, policyEnforcer);

        //read the whole stream:
        Transformer transformer = TransformerFactory.newInstance().newTransformer();
        transformer.transform(new DOMSource(document), new StreamResult(
                new OutputStream() {
                    @Override
                    public void write(int b) throws IOException {
                        // > /dev/null
                    }
                }
        ));
    }

    @Test
    public void testHttpsClientAuthenticationPolicyNegative() throws Exception {

        String policyString =
                "<wsp:ExactlyOne xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\" " +
                        "xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\">\n" +
                        "            <wsp:All>\n" +
                        "                <sp:TransportBinding>\n" +
                        "                    <wsp:Policy>\n" +
                        "                        <sp:TransportToken>\n" +
                        "                            <wsp:Policy>\n" +
                        "                                <sp:HttpsToken>\n" +
                        "                                    <!--<sp:Issuer>wsa:EndpointReferenceType</sp:Issuer>-->\n" +
                        "                                    <sp:IssuerName>CN=transmitter,OU=swssf,C=CH</sp:IssuerName>\n" +
                        "                                    <wsp:Policy>\n" +
                        "                                        <sp:RequireClientCertificate/>\n" +
                        "                                    </wsp:Policy>\n" +
                        "                                </sp:HttpsToken>\n" +
                        "                            </wsp:Policy>\n" +
                        "                        </sp:TransportToken>\n" +
                        "                        <sp:AlgorithmSuite>\n" +
                        "                            <wsp:Policy>\n" +
                        "                                <sp:Basic256/>\n" +
                        "                            </wsp:Policy>\n" +
                        "                        </sp:AlgorithmSuite>\n" +
                        "                        <sp:Layout>\n" +
                        "                            <wsp:Policy>\n" +
                        "                                <sp:Lax/>\n" +
                        "                            </wsp:Policy>\n" +
                        "                        </sp:Layout>\n" +
                        "                        <sp:IncludeTimestamp/>\n" +
                        "                    </wsp:Policy>\n" +
                        "                </sp:TransportBinding>\n" +
                        "                <sp:SignedParts>\n" +
                        "                    <sp:Body/>\n" +
                        "                    <sp:Header Name=\"Header1\" Namespace=\"...\"/>\n" +
                        "                    <sp:Header Namespace=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\"/>\n" +
                        "                </sp:SignedParts>\n" +
                        "                <sp:SignedElements>\n" +
                        "                    <sp:XPath xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">wsu:Created</sp:XPath>\n" +
                        "                </sp:SignedElements>\n" +
                        "                <sp:EncryptedParts>\n" +
                        "                    <sp:Body/>\n" +
                        "                    <sp:Header Name=\"Header2\" Namespace=\"...\"/>\n" +
                        "                    <sp:Header Namespace=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\"/>\n" +
                        "                </sp:EncryptedParts>\n" +
                        "                <sp:EncryptedElements>\n" +
                        "                    <sp:XPath xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">wsu:Created</sp:XPath>\n" +
                        "                </sp:EncryptedElements>\n" +
                        "                <sp:ContentEncryptedElements>\n" +
                        "                    <sp:XPath xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">wsu:Expires</sp:XPath>\n" +
                        "                </sp:ContentEncryptedElements>\n" +
                        "                <sp:SignedSupportingTokens>\n" +
                        "                    <wsp:Policy>\n" +
                        "                        <sp:UsernameToken sp:IncludeToken=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702/IncludeToken/AlwaysToRecipient\">\n" +
                        "                            <wsp:Policy>\n" +
                        "                                <!--<sp:HashPassword/>-->\n" +
                        "                                <sp:NoPassword/>\n" +
                        "                                <!--<sp:Created/>\n" +
                        "                                <sp:Nonce/>-->\n" +
                        "                            </wsp:Policy>\n" +
                        "                        </sp:UsernameToken>\n" +
                        "                    </wsp:Policy>\n" +
                        "                </sp:SignedSupportingTokens>\n" +
                        "            </wsp:All>\n" +
                        "        </wsp:ExactlyOne>";

        WSSSecurityProperties outSecurityProperties = new WSSSecurityProperties();
        outSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
        outSecurityProperties.setEncryptionUser("receiver");
        outSecurityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
        outSecurityProperties.setSignatureUser("transmitter");
        outSecurityProperties.setTokenUser("transmitter");
        outSecurityProperties.setUsernameTokenPasswordType(WSSConstants.UsernameTokenPasswordType.PASSWORD_NONE);
        outSecurityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());

        outSecurityProperties.addSignaturePart(new SecurePart(WSSConstants.TAG_SOAP11_BODY, SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_SOAP11_BODY, SecurePart.Modifier.Content));
        List<WSSConstants.Action> actions = new ArrayList<>();
        actions.add(WSSConstants.USERNAMETOKEN);
        actions.add(WSSConstants.TIMESTAMP);
        actions.add(WSSConstants.SIGNATURE);
        actions.add(WSSConstants.ENCRYPTION);
        outSecurityProperties.setActions(actions);

        InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
        ByteArrayOutputStream baos = doOutboundSecurity(outSecurityProperties, sourceDocument);

        WSSSecurityProperties inSecurityProperties = new WSSSecurityProperties();
        inSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
        inSecurityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
        inSecurityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());

        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);
        inSecurityProperties.addInputProcessor(new PolicyInputProcessor(policyEnforcer, null));

        HttpsTokenSecurityEvent httpsTokenSecurityEvent = new HttpsTokenSecurityEvent();
        httpsTokenSecurityEvent.setIssuerName("CN=example,OU=swssf,C=CH");
        httpsTokenSecurityEvent.setAuthenticationType(HttpsTokenSecurityEvent.AuthenticationType.HttpsClientCertificateAuthentication);
        HttpsSecurityTokenImpl httpsSecurityToken = new HttpsSecurityTokenImpl(true, "CN=example,OU=swssf,C=CH");
        httpsSecurityToken.addTokenUsage(WSSecurityTokenConstants.TOKENUSAGE_MAIN_SIGNATURE);
        httpsTokenSecurityEvent.setSecurityToken(httpsSecurityToken);

        List<SecurityEvent> securityEventList = new ArrayList<>();
        securityEventList.add(httpsTokenSecurityEvent);

        try {
            Document document = doInboundSecurity(inSecurityProperties, new ByteArrayInputStream(baos.toByteArray()), securityEventList, policyEnforcer);

            //read the whole stream:
            Transformer transformer = TransformerFactory.newInstance().newTransformer();
            transformer.transform(new DOMSource(document), new StreamResult(
                    new OutputStream() {
                        @Override
                        public void write(int b) throws IOException {
                            // > /dev/null
                        }
                    }
            ));
            fail("Exception expected");
        } catch (XMLStreamException e) {
            assertTrue(e.getCause() instanceof WSSecurityException);
            assertEquals(e.getCause().getMessage(),
                    "IssuerName in Policy (CN=transmitter,OU=swssf,C=CH) didn't match with the one in the HttpsToken (CN=example,OU=swssf,C=CH)");
            assertEquals(((WSSecurityException) e.getCause()).getFaultCode(), WSSecurityException.INVALID_SECURITY);
        }
    }

    @Test
    public void testSignatureAlgorithmSuiteNegative() throws Exception {

        String policyString =
                "<wsp:ExactlyOne xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\" " +
                        "xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\">\n" +
                        "            <wsp:All>\n" +
                        "                <sp:TransportBinding>\n" +
                        "                    <wsp:Policy>\n" +
                        "                        <sp:TransportToken>\n" +
                        "                            <wsp:Policy>\n" +
                        "                                <sp:HttpsToken>\n" +
                        "                                    <!--<sp:Issuer>wsa:EndpointReferenceType</sp:Issuer>-->\n" +
                        "                                    <sp:IssuerName>transmitter</sp:IssuerName>\n" +
                        "                                    <wsp:Policy>\n" +
                        "                                        <sp:HttpBasicAuthentication/>\n" +
                        "                                    </wsp:Policy>\n" +
                        "                                </sp:HttpsToken>\n" +
                        "                            </wsp:Policy>\n" +
                        "                        </sp:TransportToken>\n" +
                        "                        <sp:AlgorithmSuite>\n" +
                        "                            <wsp:Policy>\n" +
                        "                                <sp:Basic256/>\n" +
                        "                            </wsp:Policy>\n" +
                        "                        </sp:AlgorithmSuite>\n" +
                        "                        <sp:Layout>\n" +
                        "                            <wsp:Policy>\n" +
                        "                                <sp:Lax/>\n" +
                        "                            </wsp:Policy>\n" +
                        "                        </sp:Layout>\n" +
                        "                        <sp:IncludeTimestamp/>\n" +
                        "                    </wsp:Policy>\n" +
                        "                </sp:TransportBinding>\n" +
                        "                <sp:SignedParts>\n" +
                        "                    <sp:Body/>\n" +
                        "                    <sp:Header Name=\"Header1\" Namespace=\"...\"/>\n" +
                        "                    <sp:Header Namespace=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\"/>\n" +
                        "                </sp:SignedParts>\n" +
                        "                <sp:SignedElements>\n" +
                        "                    <sp:XPath xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">wsu:Created</sp:XPath>\n" +
                        "                </sp:SignedElements>\n" +
                        "                <sp:EncryptedParts>\n" +
                        "                    <sp:Body/>\n" +
                        "                    <sp:Header Name=\"Header2\" Namespace=\"...\"/>\n" +
                        "                    <sp:Header Namespace=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\"/>\n" +
                        "                </sp:EncryptedParts>\n" +
                        "                <sp:EncryptedElements>\n" +
                        "                    <sp:XPath xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">wsu:Created</sp:XPath>\n" +
                        "                </sp:EncryptedElements>\n" +
                        "                <sp:ContentEncryptedElements>\n" +
                        "                    <sp:XPath xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">wsu:Expires</sp:XPath>\n" +
                        "                </sp:ContentEncryptedElements>\n" +
                        "            </wsp:All>\n" +
                        "        </wsp:ExactlyOne>";

        WSSSecurityProperties outSecurityProperties = new WSSSecurityProperties();
        outSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
        outSecurityProperties.setEncryptionUser("receiver");
        outSecurityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
        outSecurityProperties.setSignatureUser("transmitter");
        outSecurityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
        outSecurityProperties.setSignatureAlgorithm("http://www.w3.org/2001/04/xmldsig-more#rsa-sha512");

        outSecurityProperties.addSignaturePart(new SecurePart(new QName(WSSConstants.TAG_WSU_TIMESTAMP.getNamespaceURI(), WSSConstants.TAG_WSU_TIMESTAMP.getLocalPart()), SecurePart.Modifier.Element));
        outSecurityProperties.addSignaturePart(new SecurePart(WSSConstants.TAG_SOAP11_BODY, SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(new QName(WSSConstants.TAG_WSU_CREATED.getNamespaceURI(), WSSConstants.TAG_WSU_CREATED.getLocalPart()), SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(new QName(WSSConstants.TAG_WSU_EXPIRES.getNamespaceURI(), WSSConstants.TAG_WSU_EXPIRES.getLocalPart()), SecurePart.Modifier.Content));
        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_SOAP11_BODY, SecurePart.Modifier.Content));
        List<WSSConstants.Action> actions = new ArrayList<>();
        actions.add(WSSConstants.TIMESTAMP);
        actions.add(WSSConstants.SIGNATURE);
        actions.add(WSSConstants.ENCRYPTION);
        outSecurityProperties.setActions(actions);

        InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
        ByteArrayOutputStream baos = doOutboundSecurity(outSecurityProperties, sourceDocument);

        WSSSecurityProperties inSecurityProperties = new WSSSecurityProperties();
        inSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
        inSecurityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
        inSecurityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
        inSecurityProperties.addIgnoreBSPRule(BSPRule.R5421);

        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);
        inSecurityProperties.addInputProcessor(new PolicyInputProcessor(policyEnforcer, null));

        HttpsTokenSecurityEvent httpsTokenSecurityEvent = new HttpsTokenSecurityEvent();
        httpsTokenSecurityEvent.setIssuerName("transmitter");
        httpsTokenSecurityEvent.setAuthenticationType(HttpsTokenSecurityEvent.AuthenticationType.HttpBasicAuthentication);
        HttpsSecurityTokenImpl httpsSecurityToken = new HttpsSecurityTokenImpl(true, "transmitter");
        httpsSecurityToken.addTokenUsage(WSSecurityTokenConstants.TOKENUSAGE_MAIN_SIGNATURE);
        httpsTokenSecurityEvent.setSecurityToken(httpsSecurityToken);

        List<SecurityEvent> securityEventList = new ArrayList<>();
        securityEventList.add(httpsTokenSecurityEvent);

        try {
            Document document = doInboundSecurity(inSecurityProperties, new ByteArrayInputStream(baos.toByteArray()), securityEventList, policyEnforcer);

            //read the whole stream:
            Transformer transformer = TransformerFactory.newInstance().newTransformer();
            transformer.transform(new DOMSource(document), new StreamResult(
                    new OutputStream() {
                        @Override
                        public void write(int b) throws IOException {
                            // > /dev/null
                        }
                    }
            ));
            fail("Exception expected");
        } catch (XMLStreamException e) {
            assertTrue(e.getCause() instanceof WSSecurityException);
            assertEquals(e.getCause().getMessage(),
                    "Asymmetric algorithm http://www.w3.org/2001/04/xmldsig-more#rsa-sha512 does not meet policy");
            assertEquals(((WSSecurityException) e.getCause()).getFaultCode(), WSSecurityException.INVALID_SECURITY);
        }
    }

    @Test
    public void testC14NAlgorithmSuiteNegative() throws Exception {

        String policyString =
                "<wsp:ExactlyOne xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\" " +
                        "xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\">\n" +
                        "            <wsp:All>\n" +
                        "                <sp:TransportBinding>\n" +
                        "                    <wsp:Policy>\n" +
                        "                        <sp:TransportToken>\n" +
                        "                            <wsp:Policy>\n" +
                        "                                <sp:HttpsToken>\n" +
                        "                                    <!--<sp:Issuer>wsa:EndpointReferenceType</sp:Issuer>-->\n" +
                        "                                    <sp:IssuerName>transmitter</sp:IssuerName>\n" +
                        "                                    <wsp:Policy>\n" +
                        "                                        <sp:HttpBasicAuthentication/>\n" +
                        "                                    </wsp:Policy>\n" +
                        "                                </sp:HttpsToken>\n" +
                        "                            </wsp:Policy>\n" +
                        "                        </sp:TransportToken>\n" +
                        "                        <sp:AlgorithmSuite>\n" +
                        "                            <wsp:Policy>\n" +
                        "                                <sp:Basic256/>\n" +
                        "                            </wsp:Policy>\n" +
                        "                        </sp:AlgorithmSuite>\n" +
                        "                        <sp:Layout>\n" +
                        "                            <wsp:Policy>\n" +
                        "                                <sp:Lax/>\n" +
                        "                            </wsp:Policy>\n" +
                        "                        </sp:Layout>\n" +
                        "                        <sp:IncludeTimestamp/>\n" +
                        "                    </wsp:Policy>\n" +
                        "                </sp:TransportBinding>\n" +
                        "                <sp:SignedParts>\n" +
                        "                    <sp:Body/>\n" +
                        "                    <sp:Header Name=\"Header1\" Namespace=\"...\"/>\n" +
                        "                    <sp:Header Namespace=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\"/>\n" +
                        "                </sp:SignedParts>\n" +
                        "                <sp:SignedElements>\n" +
                        "                    <sp:XPath xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">wsu:Created</sp:XPath>\n" +
                        "                </sp:SignedElements>\n" +
                        "                <sp:EncryptedParts>\n" +
                        "                    <sp:Body/>\n" +
                        "                    <sp:Header Name=\"Header2\" Namespace=\"...\"/>\n" +
                        "                    <sp:Header Namespace=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\"/>\n" +
                        "                </sp:EncryptedParts>\n" +
                        "                <sp:EncryptedElements>\n" +
                        "                    <sp:XPath xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">wsu:Created</sp:XPath>\n" +
                        "                </sp:EncryptedElements>\n" +
                        "                <sp:ContentEncryptedElements>\n" +
                        "                    <sp:XPath xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">wsu:Expires</sp:XPath>\n" +
                        "                </sp:ContentEncryptedElements>\n" +
                        "            </wsp:All>\n" +
                        "        </wsp:ExactlyOne>";

        WSSSecurityProperties outSecurityProperties = new WSSSecurityProperties();
        outSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
        outSecurityProperties.setEncryptionUser("receiver");
        outSecurityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
        outSecurityProperties.setSignatureUser("transmitter");
        outSecurityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
        outSecurityProperties.setSignatureCanonicalizationAlgorithm("http://www.w3.org/2006/12/xml-c14n11");

        outSecurityProperties.addSignaturePart(new SecurePart(new QName(WSSConstants.TAG_WSU_TIMESTAMP.getNamespaceURI(), WSSConstants.TAG_WSU_TIMESTAMP.getLocalPart()), SecurePart.Modifier.Element));
        outSecurityProperties.addSignaturePart(new SecurePart(WSSConstants.TAG_SOAP11_BODY  , SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(new QName(WSSConstants.TAG_WSU_CREATED.getNamespaceURI(), WSSConstants.TAG_WSU_CREATED.getLocalPart()), SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(new QName(WSSConstants.TAG_WSU_EXPIRES.getNamespaceURI(), WSSConstants.TAG_WSU_EXPIRES.getLocalPart()), SecurePart.Modifier.Content));
        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_SOAP11_BODY, SecurePart.Modifier.Content));
        List<WSSConstants.Action> actions = new ArrayList<>();
        actions.add(WSSConstants.TIMESTAMP);
        actions.add(WSSConstants.SIGNATURE);
        actions.add(WSSConstants.ENCRYPTION);
        outSecurityProperties.setActions(actions);

        InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
        ByteArrayOutputStream baos = doOutboundSecurity(outSecurityProperties, sourceDocument);

        WSSSecurityProperties inSecurityProperties = new WSSSecurityProperties();
        inSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
        inSecurityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
        inSecurityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
        inSecurityProperties.addIgnoreBSPRule(BSPRule.R5404);
        inSecurityProperties.addIgnoreBSPRule(BSPRule.R5423);
        inSecurityProperties.addIgnoreBSPRule(BSPRule.R5412);

        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);
        inSecurityProperties.addInputProcessor(new PolicyInputProcessor(policyEnforcer, null));

        HttpsTokenSecurityEvent httpsTokenSecurityEvent = new HttpsTokenSecurityEvent();
        httpsTokenSecurityEvent.setIssuerName("transmitter");
        httpsTokenSecurityEvent.setAuthenticationType(HttpsTokenSecurityEvent.AuthenticationType.HttpBasicAuthentication);
        HttpsSecurityTokenImpl httpsSecurityToken = new HttpsSecurityTokenImpl(true, "transmitter");
        httpsSecurityToken.addTokenUsage(WSSecurityTokenConstants.TOKENUSAGE_MAIN_SIGNATURE);
        httpsTokenSecurityEvent.setSecurityToken(httpsSecurityToken);

        List<SecurityEvent> securityEventList = new ArrayList<>();
        securityEventList.add(httpsTokenSecurityEvent);

        try {
            Document document = doInboundSecurity(inSecurityProperties, new ByteArrayInputStream(baos.toByteArray()), securityEventList, policyEnforcer);

            //read the whole stream:
            Transformer transformer = TransformerFactory.newInstance().newTransformer();
            transformer.transform(new DOMSource(document), new StreamResult(
                    new OutputStream() {
                        @Override
                        public void write(int b) throws IOException {
                            // > /dev/null
                        }
                    }
            ));
            fail("Exception expected");
        } catch (XMLStreamException e) {
            assertTrue(e.getCause() instanceof WSSecurityException);
            assertEquals(e.getCause().getMessage(),
                    "C14N algorithm http://www.w3.org/2006/12/xml-c14n11 does not meet policy");
            assertEquals(((WSSecurityException) e.getCause()).getFaultCode(), WSSecurityException.INVALID_SECURITY);
        }
    }

    @Test
    public void testEncryptionAlgorithmSuiteNegative() throws Exception {

        String policyString =
                "<wsp:ExactlyOne xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\" " +
                        "xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\">\n" +
                        "            <wsp:All>\n" +
                        "                <sp:TransportBinding>\n" +
                        "                    <wsp:Policy>\n" +
                        "                        <sp:TransportToken>\n" +
                        "                            <wsp:Policy>\n" +
                        "                                <sp:HttpsToken>\n" +
                        "                                    <!--<sp:Issuer>wsa:EndpointReferenceType</sp:Issuer>-->\n" +
                        "                                    <sp:IssuerName>transmitter</sp:IssuerName>\n" +
                        "                                    <wsp:Policy>\n" +
                        "                                        <sp:HttpBasicAuthentication/>\n" +
                        "                                    </wsp:Policy>\n" +
                        "                                </sp:HttpsToken>\n" +
                        "                            </wsp:Policy>\n" +
                        "                        </sp:TransportToken>\n" +
                        "                        <sp:AlgorithmSuite>\n" +
                        "                            <wsp:Policy>\n" +
                        "                                <sp:Basic256/>\n" +
                        "                            </wsp:Policy>\n" +
                        "                        </sp:AlgorithmSuite>\n" +
                        "                        <sp:Layout>\n" +
                        "                            <wsp:Policy>\n" +
                        "                                <sp:Lax/>\n" +
                        "                            </wsp:Policy>\n" +
                        "                        </sp:Layout>\n" +
                        "                        <sp:IncludeTimestamp/>\n" +
                        "                    </wsp:Policy>\n" +
                        "                </sp:TransportBinding>\n" +
                        "                <sp:SignedParts>\n" +
                        "                    <sp:Body/>\n" +
                        "                    <sp:Header Name=\"Header1\" Namespace=\"...\"/>\n" +
                        "                    <sp:Header Namespace=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\"/>\n" +
                        "                </sp:SignedParts>\n" +
                        "                <sp:SignedElements>\n" +
                        "                    <sp:XPath xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">wsu:Created</sp:XPath>\n" +
                        "                </sp:SignedElements>\n" +
                        "                <sp:EncryptedParts>\n" +
                        "                    <sp:Body/>\n" +
                        "                    <sp:Header Name=\"Header2\" Namespace=\"...\"/>\n" +
                        "                    <sp:Header Namespace=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\"/>\n" +
                        "                </sp:EncryptedParts>\n" +
                        "                <sp:EncryptedElements>\n" +
                        "                    <sp:XPath xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">wsu:Created</sp:XPath>\n" +
                        "                </sp:EncryptedElements>\n" +
                        "                <sp:ContentEncryptedElements>\n" +
                        "                    <sp:XPath xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">wsu:Expires</sp:XPath>\n" +
                        "                </sp:ContentEncryptedElements>\n" +
                        "            </wsp:All>\n" +
                        "        </wsp:ExactlyOne>";

        WSSSecurityProperties outSecurityProperties = new WSSSecurityProperties();
        outSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
        outSecurityProperties.setEncryptionUser("receiver");
        outSecurityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
        outSecurityProperties.setEncryptionSymAlgorithm("http://www.w3.org/2001/04/xmlenc#tripledes-cbc");
        outSecurityProperties.setSignatureUser("transmitter");
        outSecurityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());

        outSecurityProperties.addSignaturePart(new SecurePart(new QName(WSSConstants.TAG_WSU_TIMESTAMP.getNamespaceURI(), WSSConstants.TAG_WSU_TIMESTAMP.getLocalPart()), SecurePart.Modifier.Element));
        outSecurityProperties.addSignaturePart(new SecurePart(WSSConstants.TAG_SOAP11_BODY, SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(new QName(WSSConstants.TAG_WSU_CREATED.getNamespaceURI(), WSSConstants.TAG_WSU_CREATED.getLocalPart()), SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(new QName(WSSConstants.TAG_WSU_EXPIRES.getNamespaceURI(), WSSConstants.TAG_WSU_EXPIRES.getLocalPart()), SecurePart.Modifier.Content));
        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_SOAP11_BODY, SecurePart.Modifier.Content));
        List<WSSConstants.Action> actions = new ArrayList<>();
        actions.add(WSSConstants.TIMESTAMP);
        actions.add(WSSConstants.SIGNATURE);
        actions.add(WSSConstants.ENCRYPTION);
        outSecurityProperties.setActions(actions);

        InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
        ByteArrayOutputStream baos = doOutboundSecurity(outSecurityProperties, sourceDocument);

        WSSSecurityProperties inSecurityProperties = new WSSSecurityProperties();
        inSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
        inSecurityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
        inSecurityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());

        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);
        inSecurityProperties.addInputProcessor(new PolicyInputProcessor(policyEnforcer, null));

        HttpsTokenSecurityEvent httpsTokenSecurityEvent = new HttpsTokenSecurityEvent();
        httpsTokenSecurityEvent.setIssuerName("transmitter");
        httpsTokenSecurityEvent.setAuthenticationType(HttpsTokenSecurityEvent.AuthenticationType.HttpBasicAuthentication);
        HttpsSecurityTokenImpl httpsSecurityToken = new HttpsSecurityTokenImpl(true, "transmitter");
        httpsSecurityToken.addTokenUsage(WSSecurityTokenConstants.TOKENUSAGE_MAIN_SIGNATURE);
        httpsTokenSecurityEvent.setSecurityToken(httpsSecurityToken);

        List<SecurityEvent> securityEventList = new ArrayList<>();
        securityEventList.add(httpsTokenSecurityEvent);

        try {
            Document document = doInboundSecurity(inSecurityProperties, new ByteArrayInputStream(baos.toByteArray()), securityEventList, policyEnforcer);

            //read the whole stream:
            Transformer transformer = TransformerFactory.newInstance().newTransformer();
            transformer.transform(new DOMSource(document), new StreamResult(
                    new OutputStream() {
                        @Override
                        public void write(int b) throws IOException {
                            // > /dev/null
                        }
                    }
            ));
            fail("Exception expected");
        } catch (XMLStreamException e) {
            assertTrue(e.getCause() instanceof WSSecurityException);
            assertEquals(e.getCause().getMessage(),
                    "Encryption algorithm http://www.w3.org/2001/04/xmlenc#tripledes-cbc does not meet policy\n" +
                    "Symmetric encryption algorithm key length 192 does not meet policy");
            assertEquals(((WSSecurityException) e.getCause()).getFaultCode(), WSSecurityException.INVALID_SECURITY);
        }
    }

    /*@Test
    public void testLayoutLaxTimestampFirstNegative() throws Exception {

        String policyString =
                "<wsp:ExactlyOne xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\" " +
                        "xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\">\n" +
                        "            <wsp:All>\n" +
                        "                <sp:TransportBinding>\n" +
                        "                    <wsp:Policy>\n" +
                        "                        <sp:TransportToken>\n" +
                        "                            <wsp:Policy>\n" +
                        "                                <sp:HttpsToken>\n" +
                        "                                    <!--<sp:Issuer>wsa:EndpointReferenceType</sp:Issuer>-->\n" +
                        "                                    <sp:IssuerName>transmitter</sp:IssuerName>\n" +
                        "                                    <wsp:Policy>\n" +
                        "                                        <sp:HttpBasicAuthentication/>\n" +
                        "                                    </wsp:Policy>\n" +
                        "                                </sp:HttpsToken>\n" +
                        "                            </wsp:Policy>\n" +
                        "                        </sp:TransportToken>\n" +
                        "                        <sp:AlgorithmSuite>\n" +
                        "                            <wsp:Policy>\n" +
                        "                                <sp:Basic256/>\n" +
                        "                            </wsp:Policy>\n" +
                        "                        </sp:AlgorithmSuite>\n" +
                        "                        <sp:Layout>\n" +
                        "                            <wsp:Policy>\n" +
                        "                                <sp:LaxTsFirst/>\n" +
                        "                            </wsp:Policy>\n" +
                        "                        </sp:Layout>\n" +
                        "                        <sp:IncludeTimestamp/>\n" +
                        "                    </wsp:Policy>\n" +
                        "                </sp:TransportBinding>\n" +
                        "                <sp:SignedParts>\n" +
                        "                    <sp:Body/>\n" +
                        "                    <sp:Header Name=\"Header1\" Namespace=\"...\"/>\n" +
                        "                    <sp:Header Namespace=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\"/>\n" +
                        "                </sp:SignedParts>\n" +
                        "                <sp:SignedElements>\n" +
                        "                    <sp:XPath xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">wsu:Created</sp:XPath>\n" +
                        "                </sp:SignedElements>\n" +
                        "                <sp:EncryptedParts>\n" +
                        "                    <sp:Body/>\n" +
                        "                    <sp:Header Name=\"Header2\" Namespace=\"...\"/>\n" +
                        "                    <sp:Header Namespace=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\"/>\n" +
                        "                </sp:EncryptedParts>\n" +
                        "                <sp:EncryptedElements>\n" +
                        "                    <sp:XPath xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">wsu:Created</sp:XPath>\n" +
                        "                </sp:EncryptedElements>\n" +
                        "                <sp:ContentEncryptedElements>\n" +
                        "                    <sp:XPath xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">wsu:Expires</sp:XPath>\n" +
                        "                </sp:ContentEncryptedElements>\n" +
                        "            </wsp:All>\n" +
                        "        </wsp:ExactlyOne>";

        WSSSecurityProperties outSecurityProperties = new WSSSecurityProperties();
        outSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
        outSecurityProperties.setEncryptionUser("receiver");
        outSecurityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
        outSecurityProperties.setSignatureUser("transmitter");
        outSecurityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());

        outSecurityProperties.addSignaturePart(new SecurePart(new QName(WSSConstants.TAG_WSU_TIMESTAMP.getNamespaceURI(), WSSConstants.TAG_WSU_TIMESTAMP.getLocalPart()), SecurePart.Modifier.Element));
        outSecurityProperties.addSignaturePart(new SecurePart(WSSConstants.TAG_SOAP12_ROLEBody, SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(new QName(WSSConstants.TAG_WSU_CREATED.getNamespaceURI(), WSSConstants.TAG_WSU_CREATED.getLocalPart()), SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(new QName(WSSConstants.TAG_WSU_EXPIRES.getNamespaceURI(), WSSConstants.TAG_WSU_EXPIRES.getLocalPart()), SecurePart.Modifier.Content));
        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_SOAP12_ROLEBody, SecurePart.Modifier.Content));
        WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.TIMESTAMP, WSSConstants.SIGNATURE, WSSConstants.ENCRYPTION};
        outSecurityProperties.setActions(actions);

        InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
        ByteArrayOutputStream baos = doOutboundSecurity(outSecurityProperties, sourceDocument);

        WSSSecurityProperties inSecurityProperties = new WSSSecurityProperties();
        inSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
        inSecurityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
        inSecurityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());

        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);
        inSecurityProperties.addInputProcessor(new PolicyInputProcessor(policyEnforcer, null));

        HttpsTokenSecurityEvent httpsTokenSecurityEvent = new HttpsTokenSecurityEvent();
        httpsTokenSecurityEvent.setIssuerName("transmitter");
        httpsTokenSecurityEvent.setAuthenticationType(HttpsTokenSecurityEvent.AuthenticationType.HttpBasicAuthentication);
        HttpsSecurityTokenImpl httpsSecurityToken = new HttpsSecurityTokenImpl(true, "transmitter", null);
        httpsSecurityToken.addTokenUsage(WSTokenConstants.TOKENUSAGE_MAIN_SIGNATURE);
        httpsTokenSecurityEvent.setSecurityToken(httpsSecurityToken);

        List<SecurityEvent> securityEventList = new ArrayList<>();
        securityEventList.add(httpsTokenSecurityEvent);

        try {
            Document document = doInboundSecurity(inSecurityProperties, new ByteArrayInputStream(baos.toByteArray()), securityEventList, policyEnforcer);

            //read the whole stream:
            Transformer transformer = TransformerFactory.newInstance().newTransformer();
            transformer.transform(new DOMSource(document), new StreamResult(
                    new OutputStream() {
                        @Override
                        public void write(int b) throws IOException {
                            // > /dev/null
                        }
                    }
            ));
            fail("Exception expected");
        } catch (XMLStreamException e) {
            assertTrue(e.getCause() instanceof WSSecurityException);
            assertEquals(e.getCause().getMessage(), "An error was discovered processing the <wsse:Security> header; nested exception is: \n" +
                    "\torg.apache.wss4j.policy.stax.PolicyViolationException: \n" +
                    "Policy enforces LaxTsFirst but X509Token occured first");
        }
    }*/
}
