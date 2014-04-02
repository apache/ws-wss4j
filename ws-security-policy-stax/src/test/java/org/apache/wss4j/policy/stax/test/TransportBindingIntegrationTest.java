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

import org.apache.wss4j.common.bsp.BSPRule;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.policy.stax.PolicyEnforcer;
import org.apache.wss4j.policy.stax.PolicyInputProcessor;
import org.apache.wss4j.stax.WSSec;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.ext.WSSSecurityProperties;
import org.apache.wss4j.stax.securityToken.WSSecurityTokenConstants;
import org.apache.wss4j.stax.impl.securityToken.HttpsSecurityTokenImpl;
import org.apache.wss4j.stax.securityEvent.HttpsTokenSecurityEvent;
import org.apache.wss4j.stax.test.CallbackHandlerImpl;
import org.apache.xml.security.stax.config.Init;
import org.apache.xml.security.stax.ext.SecurePart;
import org.apache.xml.security.stax.securityEvent.SecurityEvent;
import org.junit.Assert;
import org.junit.Test;
import org.w3c.dom.Document;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import java.io.*;
import java.util.ArrayList;
import java.util.List;

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

        List<WSSConstants.Action> actions = new ArrayList<WSSConstants.Action>();
        actions.add(WSSConstants.TIMESTAMP);
        actions.add(WSSConstants.SIGNATURE);
        actions.add(WSSConstants.ENCRYPT);
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
        httpsSecurityToken.addTokenUsage(WSSecurityTokenConstants.TokenUsage_MainSignature);
        httpsTokenSecurityEvent.setSecurityToken(httpsSecurityToken);

        List<SecurityEvent> securityEventList = new ArrayList<SecurityEvent>();
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

        List<WSSConstants.Action> actions = new ArrayList<WSSConstants.Action>();
        actions.add(WSSConstants.SIGNATURE);
        actions.add(WSSConstants.ENCRYPT);
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
        httpsSecurityToken.addTokenUsage(WSSecurityTokenConstants.TokenUsage_MainSignature);
        httpsTokenSecurityEvent.setSecurityToken(httpsSecurityToken);

        List<SecurityEvent> securityEventList = new ArrayList<SecurityEvent>();
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
            Assert.fail("Exception expected");
        } catch (XMLStreamException e) {
            Assert.assertTrue(e.getCause() instanceof WSSecurityException);
            Assert.assertEquals(e.getCause().getMessage(),
                    "Element /{http://schemas.xmlsoap.org/soap/envelope/}Envelope/{http://schemas.xmlsoap.org/soap/envelope/}Header/{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd}Security/{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd}Timestamp must be present");
            Assert.assertEquals(((WSSecurityException) e.getCause()).getFaultCode(), WSSecurityException.INVALID_SECURITY);
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

        List<WSSConstants.Action> actions = new ArrayList<WSSConstants.Action>();
        actions.add(WSSConstants.USERNAMETOKEN);
        actions.add(WSSConstants.TIMESTAMP);
        actions.add(WSSConstants.SIGNATURE);
        actions.add(WSSConstants.ENCRYPT);
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
        httpsSecurityToken.addTokenUsage(WSSecurityTokenConstants.TokenUsage_MainSignature);
        httpsTokenSecurityEvent.setSecurityToken(httpsSecurityToken);

        List<SecurityEvent> securityEventList = new ArrayList<SecurityEvent>();
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

        List<WSSConstants.Action> actions = new ArrayList<WSSConstants.Action>();
        actions.add(WSSConstants.TIMESTAMP);
        actions.add(WSSConstants.SIGNATURE);
        actions.add(WSSConstants.ENCRYPT);
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
        httpsSecurityToken.addTokenUsage(WSSecurityTokenConstants.TokenUsage_MainSignature);
        httpsTokenSecurityEvent.setSecurityToken(httpsSecurityToken);

        List<SecurityEvent> securityEventList = new ArrayList<SecurityEvent>();
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
            Assert.fail("Exception expected");
        } catch (XMLStreamException e) {
            Assert.assertTrue(e.getCause() instanceof WSSecurityException);
            Assert.assertEquals(e.getCause().getMessage(),
                    "Assertion {http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702}UsernameToken not satisfied");
            Assert.assertEquals(((WSSecurityException) e.getCause()).getFaultCode(), WSSecurityException.INVALID_SECURITY);
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

        List<WSSConstants.Action> actions = new ArrayList<WSSConstants.Action>();
        actions.add(WSSConstants.SIGNATURE);
        actions.add(WSSConstants.ENCRYPT);
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
        httpsSecurityToken.addTokenUsage(WSSecurityTokenConstants.TokenUsage_MainSignature);
        httpsTokenSecurityEvent.setSecurityToken(httpsSecurityToken);

        List<SecurityEvent> securityEventList = new ArrayList<SecurityEvent>();
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
            Assert.fail("Exception expected");
        } catch (XMLStreamException e) {
            Assert.assertTrue(e.getCause() instanceof WSSecurityException);
            Assert.assertEquals(e.getCause().getMessage(),
                    "Assertion {http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702}UsernameToken not satisfied");
            Assert.assertEquals(((WSSecurityException) e.getCause()).getFaultCode(), WSSecurityException.INVALID_SECURITY);
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

        List<WSSConstants.Action> actions = new ArrayList<WSSConstants.Action>();
        actions.add(WSSConstants.USERNAMETOKEN);
        actions.add(WSSConstants.TIMESTAMP);
        actions.add(WSSConstants.SIGNATURE);
        actions.add(WSSConstants.ENCRYPT);
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
        httpsSecurityToken.addTokenUsage(WSSecurityTokenConstants.TokenUsage_MainSignature);
        httpsTokenSecurityEvent.setSecurityToken(httpsSecurityToken);

        List<SecurityEvent> securityEventList = new ArrayList<SecurityEvent>();
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

        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_soap11_Body, SecurePart.Modifier.Content));
        List<WSSConstants.Action> actions = new ArrayList<WSSConstants.Action>();
        actions.add(WSSConstants.USERNAMETOKEN);
        actions.add(WSSConstants.TIMESTAMP);
        actions.add(WSSConstants.ENCRYPT);
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
        httpsSecurityToken.addTokenUsage(WSSecurityTokenConstants.TokenUsage_MainSignature);
        httpsTokenSecurityEvent.setSecurityToken(httpsSecurityToken);

        List<SecurityEvent> securityEventList = new ArrayList<SecurityEvent>();
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

        outSecurityProperties.addSignaturePart(new SecurePart(WSSConstants.TAG_soap11_Body, SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_soap11_Body, SecurePart.Modifier.Content));
        List<WSSConstants.Action> actions = new ArrayList<WSSConstants.Action>();
        actions.add(WSSConstants.USERNAMETOKEN);
        actions.add(WSSConstants.TIMESTAMP);
        actions.add(WSSConstants.SIGNATURE);
        actions.add(WSSConstants.ENCRYPT);
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
        httpsSecurityToken.addTokenUsage(WSSecurityTokenConstants.TokenUsage_MainSignature);
        httpsTokenSecurityEvent.setSecurityToken(httpsSecurityToken);

        List<SecurityEvent> securityEventList = new ArrayList<SecurityEvent>();
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

        outSecurityProperties.addSignaturePart(new SecurePart(WSSConstants.TAG_soap11_Body, SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_soap11_Body, SecurePart.Modifier.Content));
        List<WSSConstants.Action> actions = new ArrayList<WSSConstants.Action>();
        actions.add(WSSConstants.USERNAMETOKEN);
        actions.add(WSSConstants.TIMESTAMP);
        actions.add(WSSConstants.SIGNATURE);
        actions.add(WSSConstants.ENCRYPT);
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
        httpsSecurityToken.addTokenUsage(WSSecurityTokenConstants.TokenUsage_MainSignature);
        httpsTokenSecurityEvent.setSecurityToken(httpsSecurityToken);

        List<SecurityEvent> securityEventList = new ArrayList<SecurityEvent>();
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
            Assert.fail("Exception expected");
        } catch (XMLStreamException e) {
            Assert.assertTrue(e.getCause() instanceof WSSecurityException);
            Assert.assertEquals(e.getCause().getMessage(),
                    "IssuerName in Policy (CN=transmitter,OU=swssf,C=CH) didn't match with the one in the HttpsToken (CN=example,OU=swssf,C=CH)");
            Assert.assertEquals(((WSSecurityException) e.getCause()).getFaultCode(), WSSecurityException.INVALID_SECURITY);
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

        outSecurityProperties.addSignaturePart(new SecurePart(new QName(WSSConstants.TAG_wsu_Timestamp.getNamespaceURI(), WSSConstants.TAG_wsu_Timestamp.getLocalPart()), SecurePart.Modifier.Element));
        outSecurityProperties.addSignaturePart(new SecurePart(WSSConstants.TAG_soap11_Body, SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(new QName(WSSConstants.TAG_wsu_Created.getNamespaceURI(), WSSConstants.TAG_wsu_Created.getLocalPart()), SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(new QName(WSSConstants.TAG_wsu_Expires.getNamespaceURI(), WSSConstants.TAG_wsu_Expires.getLocalPart()), SecurePart.Modifier.Content));
        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_soap11_Body, SecurePart.Modifier.Content));
        List<WSSConstants.Action> actions = new ArrayList<WSSConstants.Action>();
        actions.add(WSSConstants.TIMESTAMP);
        actions.add(WSSConstants.SIGNATURE);
        actions.add(WSSConstants.ENCRYPT);
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
        httpsSecurityToken.addTokenUsage(WSSecurityTokenConstants.TokenUsage_MainSignature);
        httpsTokenSecurityEvent.setSecurityToken(httpsSecurityToken);

        List<SecurityEvent> securityEventList = new ArrayList<SecurityEvent>();
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
            Assert.fail("Exception expected");
        } catch (XMLStreamException e) {
            Assert.assertTrue(e.getCause() instanceof WSSecurityException);
            Assert.assertEquals(e.getCause().getMessage(),
                    "Asymmetric algorithm http://www.w3.org/2001/04/xmldsig-more#rsa-sha512 does not meet policy");
            Assert.assertEquals(((WSSecurityException) e.getCause()).getFaultCode(), WSSecurityException.INVALID_SECURITY);
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

        outSecurityProperties.addSignaturePart(new SecurePart(new QName(WSSConstants.TAG_wsu_Timestamp.getNamespaceURI(), WSSConstants.TAG_wsu_Timestamp.getLocalPart()), SecurePart.Modifier.Element));
        outSecurityProperties.addSignaturePart(new SecurePart(WSSConstants.TAG_soap11_Body  , SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(new QName(WSSConstants.TAG_wsu_Created.getNamespaceURI(), WSSConstants.TAG_wsu_Created.getLocalPart()), SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(new QName(WSSConstants.TAG_wsu_Expires.getNamespaceURI(), WSSConstants.TAG_wsu_Expires.getLocalPart()), SecurePart.Modifier.Content));
        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_soap11_Body, SecurePart.Modifier.Content));
        List<WSSConstants.Action> actions = new ArrayList<WSSConstants.Action>();
        actions.add(WSSConstants.TIMESTAMP);
        actions.add(WSSConstants.SIGNATURE);
        actions.add(WSSConstants.ENCRYPT);
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
        httpsSecurityToken.addTokenUsage(WSSecurityTokenConstants.TokenUsage_MainSignature);
        httpsTokenSecurityEvent.setSecurityToken(httpsSecurityToken);

        List<SecurityEvent> securityEventList = new ArrayList<SecurityEvent>();
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
            Assert.fail("Exception expected");
        } catch (XMLStreamException e) {
            Assert.assertTrue(e.getCause() instanceof WSSecurityException);
            Assert.assertEquals(e.getCause().getMessage(),
                    "C14N algorithm http://www.w3.org/2006/12/xml-c14n11 does not meet policy");
            Assert.assertEquals(((WSSecurityException) e.getCause()).getFaultCode(), WSSecurityException.INVALID_SECURITY);
        }
    }

    @Test
    public void testSignatureDigestAlgorithmSuiteNegative() throws Exception {

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
        outSecurityProperties.setSignatureDigestAlgorithm("http://www.w3.org/2001/04/xmldsig-more#rsa-md5");

        outSecurityProperties.addSignaturePart(new SecurePart(new QName(WSSConstants.TAG_wsu_Timestamp.getNamespaceURI(), WSSConstants.TAG_wsu_Timestamp.getLocalPart()), SecurePart.Modifier.Element, new String[]{WSSConstants.NS_C14N_EXCL}, "http://www.w3.org/2001/04/xmldsig-more#md5"));
        outSecurityProperties.addSignaturePart(new SecurePart(WSSConstants.TAG_soap11_Body, SecurePart.Modifier.Element, new String[]{WSSConstants.NS_C14N_EXCL}, "http://www.w3.org/2001/04/xmldsig-more#md5"));
        outSecurityProperties.addEncryptionPart(new SecurePart(new QName(WSSConstants.TAG_wsu_Created.getNamespaceURI(), WSSConstants.TAG_wsu_Created.getLocalPart()), SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(new QName(WSSConstants.TAG_wsu_Expires.getNamespaceURI(), WSSConstants.TAG_wsu_Expires.getLocalPart()), SecurePart.Modifier.Content));
        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_soap11_Body, SecurePart.Modifier.Content));
        List<WSSConstants.Action> actions = new ArrayList<WSSConstants.Action>();
        actions.add(WSSConstants.TIMESTAMP);
        actions.add(WSSConstants.SIGNATURE);
        actions.add(WSSConstants.ENCRYPT);
        outSecurityProperties.setActions(actions);

        InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
        ByteArrayOutputStream baos = doOutboundSecurity(outSecurityProperties, sourceDocument);

        WSSSecurityProperties inSecurityProperties = new WSSSecurityProperties();
        inSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
        inSecurityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
        inSecurityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
        inSecurityProperties.addIgnoreBSPRule(BSPRule.R5420);

        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);
        inSecurityProperties.addInputProcessor(new PolicyInputProcessor(policyEnforcer, null));

        HttpsTokenSecurityEvent httpsTokenSecurityEvent = new HttpsTokenSecurityEvent();
        httpsTokenSecurityEvent.setIssuerName("transmitter");
        httpsTokenSecurityEvent.setAuthenticationType(HttpsTokenSecurityEvent.AuthenticationType.HttpBasicAuthentication);
        HttpsSecurityTokenImpl httpsSecurityToken = new HttpsSecurityTokenImpl(true, "transmitter");
        httpsSecurityToken.addTokenUsage(WSSecurityTokenConstants.TokenUsage_MainSignature);
        httpsTokenSecurityEvent.setSecurityToken(httpsSecurityToken);

        List<SecurityEvent> securityEventList = new ArrayList<SecurityEvent>();
        securityEventList.add(httpsTokenSecurityEvent);

        try {
            Init.init(WSSec.class.getClassLoader().getResource("wss/wss-config.xml").toURI(), WSSec.class);
            switchAllowMD5Algorithm(true);
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
            Assert.fail("Exception expected");
        } catch (XMLStreamException e) {
            Assert.assertTrue(e.getCause() instanceof WSSecurityException);
            Assert.assertEquals(e.getCause().getMessage(),
                    "Digest algorithm http://www.w3.org/2001/04/xmldsig-more#md5 does not meet policy");
            Assert.assertEquals(((WSSecurityException) e.getCause()).getFaultCode(), WSSecurityException.INVALID_SECURITY);
        } finally {
            switchAllowMD5Algorithm(false);
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

        outSecurityProperties.addSignaturePart(new SecurePart(new QName(WSSConstants.TAG_wsu_Timestamp.getNamespaceURI(), WSSConstants.TAG_wsu_Timestamp.getLocalPart()), SecurePart.Modifier.Element));
        outSecurityProperties.addSignaturePart(new SecurePart(WSSConstants.TAG_soap11_Body, SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(new QName(WSSConstants.TAG_wsu_Created.getNamespaceURI(), WSSConstants.TAG_wsu_Created.getLocalPart()), SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(new QName(WSSConstants.TAG_wsu_Expires.getNamespaceURI(), WSSConstants.TAG_wsu_Expires.getLocalPart()), SecurePart.Modifier.Content));
        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_soap11_Body, SecurePart.Modifier.Content));
        List<WSSConstants.Action> actions = new ArrayList<WSSConstants.Action>();
        actions.add(WSSConstants.TIMESTAMP);
        actions.add(WSSConstants.SIGNATURE);
        actions.add(WSSConstants.ENCRYPT);
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
        httpsSecurityToken.addTokenUsage(WSSecurityTokenConstants.TokenUsage_MainSignature);
        httpsTokenSecurityEvent.setSecurityToken(httpsSecurityToken);

        List<SecurityEvent> securityEventList = new ArrayList<SecurityEvent>();
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
            Assert.fail("Exception expected");
        } catch (XMLStreamException e) {
            Assert.assertTrue(e.getCause() instanceof WSSecurityException);
            Assert.assertEquals(e.getCause().getMessage(),
                    "Encryption algorithm http://www.w3.org/2001/04/xmlenc#tripledes-cbc does not meet policy\n" +
                    "Symmetric encryption algorithm key length 192 does not meet policy");
            Assert.assertEquals(((WSSecurityException) e.getCause()).getFaultCode(), WSSecurityException.INVALID_SECURITY);
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

        outSecurityProperties.addSignaturePart(new SecurePart(new QName(WSSConstants.TAG_wsu_Timestamp.getNamespaceURI(), WSSConstants.TAG_wsu_Timestamp.getLocalPart()), SecurePart.Modifier.Element));
        outSecurityProperties.addSignaturePart(new SecurePart(WSSConstants.TAG_soap12_Body, SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(new QName(WSSConstants.TAG_wsu_Created.getNamespaceURI(), WSSConstants.TAG_wsu_Created.getLocalPart()), SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(new QName(WSSConstants.TAG_wsu_Expires.getNamespaceURI(), WSSConstants.TAG_wsu_Expires.getLocalPart()), SecurePart.Modifier.Content));
        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_soap12_Body, SecurePart.Modifier.Content));
        WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.TIMESTAMP, WSSConstants.SIGNATURE, WSSConstants.ENCRYPT};
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
        httpsSecurityToken.addTokenUsage(WSTokenConstants.TokenUsage_MainSignature);
        httpsTokenSecurityEvent.setSecurityToken(httpsSecurityToken);

        List<SecurityEvent> securityEventList = new ArrayList<SecurityEvent>();
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
            Assert.fail("Exception expected");
        } catch (XMLStreamException e) {
            Assert.assertTrue(e.getCause() instanceof WSSecurityException);
            Assert.assertEquals(e.getCause().getMessage(), "An error was discovered processing the <wsse:Security> header; nested exception is: \n" +
                    "\torg.apache.wss4j.policy.stax.PolicyViolationException: \n" +
                    "Policy enforces LaxTsFirst but X509Token occured first");
        }
    }*/
}
