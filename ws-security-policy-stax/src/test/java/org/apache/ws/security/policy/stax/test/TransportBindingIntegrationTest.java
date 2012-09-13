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
package org.apache.ws.security.policy.stax.test;

import org.apache.ws.security.common.bsp.BSPRule;
import org.apache.ws.security.common.ext.WSSecurityException;
import org.apache.ws.security.policy.stax.PolicyEnforcer;
import org.apache.ws.security.policy.stax.PolicyInputProcessor;
import org.apache.ws.security.stax.WSSec;
import org.apache.ws.security.stax.ext.WSSConstants;
import org.apache.ws.security.stax.ext.WSSSecurityProperties;
import org.apache.ws.security.stax.impl.securityToken.HttpsSecurityToken;
import org.apache.ws.security.stax.securityEvent.HttpsTokenSecurityEvent;
import org.apache.ws.security.stax.test.CallbackHandlerImpl;
import org.apache.xml.security.stax.config.Init;
import org.apache.xml.security.stax.ext.SecurePart;
import org.apache.xml.security.stax.ext.SecurityToken;
import org.apache.xml.security.stax.securityEvent.SecurityEvent;
import org.testng.Assert;
import org.testng.annotations.Test;
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

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
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

        WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.TIMESTAMP, WSSConstants.SIGNATURE, WSSConstants.ENCRYPT};
        outSecurityProperties.setOutAction(actions);

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
        HttpsSecurityToken httpsSecurityToken = new HttpsSecurityToken(true, "transmitter", null);
        httpsSecurityToken.addTokenUsage(SecurityToken.TokenUsage.MainSignature);
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

        WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.SIGNATURE, WSSConstants.ENCRYPT};
        outSecurityProperties.setOutAction(actions);

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
        HttpsSecurityToken httpsSecurityToken = new HttpsSecurityToken(true, "transmitter", null);
        httpsSecurityToken.addTokenUsage(SecurityToken.TokenUsage.MainSignature);
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
                    "\torg.apache.ws.security.policy.WSSPolicyException: \n" +
                    "Element /{http://schemas.xmlsoap.org/soap/envelope/}Envelope/{http://schemas.xmlsoap.org/soap/envelope/}Header/{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd}Security/{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd}Timestamp must be present");
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
                        "                        <sp:UsernameToken IncludeToken=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702/IncludeToken/AlwaysToRecipient\">\n" +
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

        WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.USERNAMETOKEN, WSSConstants.TIMESTAMP, WSSConstants.SIGNATURE, WSSConstants.ENCRYPT};
        outSecurityProperties.setOutAction(actions);

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
        HttpsSecurityToken httpsSecurityToken = new HttpsSecurityToken(true, "transmitter", null);
        httpsSecurityToken.addTokenUsage(SecurityToken.TokenUsage.MainSignature);
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
                        "                        <sp:UsernameToken IncludeToken=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702/IncludeToken/AlwaysToRecipient\">\n" +
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

        WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.TIMESTAMP, WSSConstants.SIGNATURE, WSSConstants.ENCRYPT};
        outSecurityProperties.setOutAction(actions);

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
        HttpsSecurityToken httpsSecurityToken = new HttpsSecurityToken(true, "transmitter", null);
        httpsSecurityToken.addTokenUsage(SecurityToken.TokenUsage.MainSignature);
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
                    "\torg.apache.ws.security.policy.WSSPolicyException: Assertion {http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702}UsernameToken not satisfied");
        }
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
                        "                        <sp:UsernameToken IncludeToken=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702/IncludeToken/AlwaysToRecipient\">\n" +
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
        WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.USERNAMETOKEN, WSSConstants.TIMESTAMP, WSSConstants.ENCRYPT};
        outSecurityProperties.setOutAction(actions);

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
        HttpsSecurityToken httpsSecurityToken = new HttpsSecurityToken(true, "transmitter", null);
        httpsSecurityToken.addTokenUsage(SecurityToken.TokenUsage.MainSignature);
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
                        "                        <sp:UsernameToken IncludeToken=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702/IncludeToken/AlwaysToRecipient\">\n" +
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
        WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.USERNAMETOKEN, WSSConstants.TIMESTAMP, WSSConstants.SIGNATURE, WSSConstants.ENCRYPT};
        outSecurityProperties.setOutAction(actions);

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
        HttpsSecurityToken httpsSecurityToken = new HttpsSecurityToken(true, "CN=transmitter,OU=swssf,C=CH", null);
        httpsSecurityToken.addTokenUsage(SecurityToken.TokenUsage.MainSignature);
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
                        "                        <sp:UsernameToken IncludeToken=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702/IncludeToken/AlwaysToRecipient\">\n" +
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
        WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.USERNAMETOKEN, WSSConstants.TIMESTAMP, WSSConstants.SIGNATURE, WSSConstants.ENCRYPT};
        outSecurityProperties.setOutAction(actions);

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
        HttpsSecurityToken httpsSecurityToken = new HttpsSecurityToken(true, "CN=example,OU=swssf,C=CH", null);
        httpsSecurityToken.addTokenUsage(SecurityToken.TokenUsage.MainSignature);
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
                    "\torg.apache.ws.security.policy.stax.PolicyViolationException: \n" +
                    "IssuerName in Policy (CN=transmitter,OU=swssf,C=CH) didn't match with the one in the HttpsToken (CN=example,OU=swssf,C=CH)");
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
        outSecurityProperties.addSignaturePart(new SecurePart(WSSConstants.TAG_soap12_Body, SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(new QName(WSSConstants.TAG_wsu_Created.getNamespaceURI(), WSSConstants.TAG_wsu_Created.getLocalPart()), SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(new QName(WSSConstants.TAG_wsu_Expires.getNamespaceURI(), WSSConstants.TAG_wsu_Expires.getLocalPart()), SecurePart.Modifier.Content));
        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_soap12_Body, SecurePart.Modifier.Content));
        WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.TIMESTAMP, WSSConstants.SIGNATURE, WSSConstants.ENCRYPT};
        outSecurityProperties.setOutAction(actions);

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
        HttpsSecurityToken httpsSecurityToken = new HttpsSecurityToken(true, "transmitter", null);
        httpsSecurityToken.addTokenUsage(SecurityToken.TokenUsage.MainSignature);
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
                    "\torg.apache.ws.security.policy.stax.PolicyViolationException: \n" +
                    "Asymmetric algorithm http://www.w3.org/2001/04/xmldsig-more#rsa-sha512 does not meet policy");
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
        outSecurityProperties.addSignaturePart(new SecurePart(WSSConstants.TAG_soap12_Body, SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(new QName(WSSConstants.TAG_wsu_Created.getNamespaceURI(), WSSConstants.TAG_wsu_Created.getLocalPart()), SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(new QName(WSSConstants.TAG_wsu_Expires.getNamespaceURI(), WSSConstants.TAG_wsu_Expires.getLocalPart()), SecurePart.Modifier.Content));
        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_soap12_Body, SecurePart.Modifier.Content));
        WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.TIMESTAMP, WSSConstants.SIGNATURE, WSSConstants.ENCRYPT};
        outSecurityProperties.setOutAction(actions);

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
        HttpsSecurityToken httpsSecurityToken = new HttpsSecurityToken(true, "transmitter", null);
        httpsSecurityToken.addTokenUsage(SecurityToken.TokenUsage.MainSignature);
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
                    "\torg.apache.ws.security.policy.stax.PolicyViolationException: \n" +
                    "C14N algorithm http://www.w3.org/2006/12/xml-c14n11 does not meet policy");
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
        outSecurityProperties.addSignaturePart(new SecurePart(WSSConstants.TAG_soap12_Body, SecurePart.Modifier.Element, new String[]{WSSConstants.NS_C14N_EXCL}, "http://www.w3.org/2001/04/xmldsig-more#md5"));
        outSecurityProperties.addEncryptionPart(new SecurePart(new QName(WSSConstants.TAG_wsu_Created.getNamespaceURI(), WSSConstants.TAG_wsu_Created.getLocalPart()), SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(new QName(WSSConstants.TAG_wsu_Expires.getNamespaceURI(), WSSConstants.TAG_wsu_Expires.getLocalPart()), SecurePart.Modifier.Content));
        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_soap12_Body, SecurePart.Modifier.Content));
        WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.TIMESTAMP, WSSConstants.SIGNATURE, WSSConstants.ENCRYPT};
        outSecurityProperties.setOutAction(actions);

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
        HttpsSecurityToken httpsSecurityToken = new HttpsSecurityToken(true, "transmitter", null);
        httpsSecurityToken.addTokenUsage(SecurityToken.TokenUsage.MainSignature);
        httpsTokenSecurityEvent.setSecurityToken(httpsSecurityToken);

        List<SecurityEvent> securityEventList = new ArrayList<SecurityEvent>();
        securityEventList.add(httpsTokenSecurityEvent);

        try {
            Init.init(WSSec.class.getClassLoader().getResource("wss/wss-config.xml").toURI());
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
            Assert.assertEquals(e.getCause().getMessage(), "An error was discovered processing the <wsse:Security> header; nested exception is: \n" +
                    "\torg.apache.ws.security.policy.stax.PolicyViolationException: \n" +
                    "Digest algorithm http://www.w3.org/2001/04/xmldsig-more#md5 does not meet policy");
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
        outSecurityProperties.addSignaturePart(new SecurePart(WSSConstants.TAG_soap12_Body, SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(new QName(WSSConstants.TAG_wsu_Created.getNamespaceURI(), WSSConstants.TAG_wsu_Created.getLocalPart()), SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(new QName(WSSConstants.TAG_wsu_Expires.getNamespaceURI(), WSSConstants.TAG_wsu_Expires.getLocalPart()), SecurePart.Modifier.Content));
        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_soap12_Body, SecurePart.Modifier.Content));
        WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.TIMESTAMP, WSSConstants.SIGNATURE, WSSConstants.ENCRYPT};
        outSecurityProperties.setOutAction(actions);

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
        HttpsSecurityToken httpsSecurityToken = new HttpsSecurityToken(true, "transmitter", null);
        httpsSecurityToken.addTokenUsage(SecurityToken.TokenUsage.MainSignature);
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
                    "\torg.apache.ws.security.policy.stax.PolicyViolationException: \n" +
                    "Encryption algorithm http://www.w3.org/2001/04/xmlenc#tripledes-cbc does not meet policy\n" +
                    "Symmetric encryption algorithm key length 192 does not meet policy");
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
        outSecurityProperties.setOutAction(actions);

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
        HttpsSecurityToken httpsSecurityToken = new HttpsSecurityToken(true, "transmitter", null);
        httpsSecurityToken.addTokenUsage(SecurityToken.TokenUsage.MainSignature);
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
                    "\torg.apache.ws.security.policy.stax.PolicyViolationException: \n" +
                    "Policy enforces LaxTsFirst but X509Token occured first");
        }
    }*/
}
