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
package org.swssf.policy.test;

import org.apache.ws.security.saml.ext.builder.SAML2Constants;
import org.opensaml.common.SAMLVersion;
import org.swssf.policy.PolicyEnforcer;
import org.swssf.policy.PolicyInputProcessor;
import org.swssf.wss.ext.WSSConstants;
import org.swssf.wss.ext.WSSSecurityProperties;
import org.swssf.wss.ext.WSSecurityException;
import org.swssf.wss.test.CallbackHandlerImpl;
import org.apache.xml.security.stax.crypto.CryptoType;
import org.apache.xml.security.stax.crypto.Merlin;
import org.apache.xml.security.stax.ext.SecurePart;
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
import java.security.KeyStore;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class AsymmetricBindingIntegrationTest extends AbstractPolicyTestBase {

    @Test
    public void testIncludeTimestampPolicy() throws Exception {

        String policyString =
                "<wsp:ExactlyOne xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\" " +
                        "xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\">\n" +
                        "            <wsp:All>\n" +
                        "                <sp:AsymmetricBinding>\n" +
                        "                    <wsp:Policy>\n" +
                        "                        <sp:InitiatorToken>\n" +
                        "                            <wsp:Policy>\n" +
                        "                                <sp:X509Token IncludeToken=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702/IncludeToken/AlwaysToRecipient\">\n" +
                        "                                    <sp:IssuerName>CN=transmitter,OU=swssf,C=CH</sp:IssuerName>\n" +
                        "                                    <wsp:Policy>\n" +
                        "                                        <sp:WssX509V3Token11/>\n" +
                        "                                    </wsp:Policy>\n" +
                        "                                </sp:X509Token>\n" +
                        "                            </wsp:Policy>\n" +
                        "                        </sp:InitiatorToken>\n" +
                        "                        <sp:RecipientToken>\n" +
                        "                            <wsp:Policy>\n" +
                        "                              <sp:X509Token IncludeToken=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702/IncludeToken/AlwaysToRecipient\">\n" +
                        "                                  <sp:IssuerName>CN=receiver,OU=swssf,C=CH</sp:IssuerName>\n" +
                        "                                  <wsp:Policy>\n" +
                        "                                      <sp:WssX509V3Token11/>\n" +
                        "                                  </wsp:Policy>\n" +
                        "                              </sp:X509Token>\n" +
                        "                            </wsp:Policy>\n" +
                        "                         </sp:RecipientToken>\n" +
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
                        "                </sp:AsymmetricBinding>\n" +
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

        outSecurityProperties.addSignaturePart(new SecurePart(WSSConstants.TAG_wsu_Timestamp, SecurePart.Modifier.Element));
        outSecurityProperties.addSignaturePart(new SecurePart(WSSConstants.TAG_soap11_Body, SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_wsu_Created, SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_wsu_Expires, SecurePart.Modifier.Content));
        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_soap11_Body, SecurePart.Modifier.Content));
        WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.TIMESTAMP, WSSConstants.SIGNATURE, WSSConstants.ENCRYPT};
        outSecurityProperties.setOutAction(actions);

        InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
        ByteArrayOutputStream baos = doOutboundSecurity(outSecurityProperties, sourceDocument);

        WSSSecurityProperties inSecurityProperties = new WSSSecurityProperties();
        inSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
        inSecurityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
        inSecurityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());

        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);
        inSecurityProperties.addInputProcessor(new PolicyInputProcessor(policyEnforcer, inSecurityProperties));

        Document document = doInboundSecurity(inSecurityProperties, new ByteArrayInputStream(baos.toByteArray()), policyEnforcer);

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
    public void testIncludeTimestampPolicy2ndAlternative() throws Exception {

        String policyString =
                "<wsp:ExactlyOne xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\" " +
                        "xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\">\n" +
                        "            <wsp:All>\n" +
                        "                <sp:AsymmetricBinding>\n" +
                        "                    <wsp:Policy>\n" +
                        "                       <wsp:ExactlyOne>\n" +
                        "                       <wsp:All>\n" +
                        "                        <sp:InitiatorToken>\n" +
                        "                            <wsp:Policy>\n" +
                        "                                <sp:X509Token IncludeToken=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702/IncludeToken/AlwaysToRecipient\">\n" +
                        "                                    <sp:IssuerName>CN=transmitter,OU=swssf,C=CH</sp:IssuerName>\n" +
                        "                                    <wsp:Policy>\n" +
                        "                                        <sp:WssX509V1Token11/>\n" +
                        "                                    </wsp:Policy>\n" +
                        "                                </sp:X509Token>\n" +
                        "                            </wsp:Policy>\n" +
                        "                        </sp:InitiatorToken>\n" +
                        "                        <sp:RecipientToken>\n" +
                        "                            <wsp:Policy>\n" +
                        "                              <sp:X509Token IncludeToken=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702/IncludeToken/AlwaysToRecipient\">\n" +
                        "                                  <sp:IssuerName>CN=receiver,OU=swssf,C=CH</sp:IssuerName>\n" +
                        "                                  <wsp:Policy>\n" +
                        "                                      <sp:WssX509V3Token11/>\n" +
                        "                                  </wsp:Policy>\n" +
                        "                              </sp:X509Token>\n" +
                        "                            </wsp:Policy>\n" +
                        "                         </sp:RecipientToken>\n" +
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
                        "                       </wsp:All>\n" +
                        "                       <wsp:All>\n" +
                        "                        <sp:InitiatorToken>\n" +
                        "                            <wsp:Policy>\n" +
                        "                                <sp:X509Token IncludeToken=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702/IncludeToken/AlwaysToRecipient\">\n" +
                        "                                    <sp:IssuerName>CN=transmitter,OU=swssf,C=CH</sp:IssuerName>\n" +
                        "                                    <wsp:Policy>\n" +
                        "                                        <sp:WssX509V3Token11/>\n" +
                        "                                    </wsp:Policy>\n" +
                        "                                </sp:X509Token>\n" +
                        "                            </wsp:Policy>\n" +
                        "                        </sp:InitiatorToken>\n" +
                        "                        <sp:RecipientToken>\n" +
                        "                            <wsp:Policy>\n" +
                        "                              <sp:X509Token IncludeToken=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702/IncludeToken/AlwaysToRecipient\">\n" +
                        "                                  <sp:IssuerName>CN=receiver,OU=swssf,C=CH</sp:IssuerName>\n" +
                        "                                  <wsp:Policy>\n" +
                        "                                      <sp:WssX509V3Token11/>\n" +
                        "                                  </wsp:Policy>\n" +
                        "                              </sp:X509Token>\n" +
                        "                            </wsp:Policy>\n" +
                        "                         </sp:RecipientToken>\n" +
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
                        "                       </wsp:All>\n" +
                        "                       </wsp:ExactlyOne>\n" +
                        "                    </wsp:Policy>\n" +
                        "                </sp:AsymmetricBinding>\n" +
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

        outSecurityProperties.addSignaturePart(new SecurePart(WSSConstants.TAG_wsu_Timestamp, SecurePart.Modifier.Element));
        outSecurityProperties.addSignaturePart(new SecurePart(WSSConstants.TAG_soap11_Body, SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_wsu_Created, SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_wsu_Expires, SecurePart.Modifier.Content));
        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_soap11_Body, SecurePart.Modifier.Content));
        WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.TIMESTAMP, WSSConstants.SIGNATURE, WSSConstants.ENCRYPT};
        outSecurityProperties.setOutAction(actions);

        InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
        ByteArrayOutputStream baos = doOutboundSecurity(outSecurityProperties, sourceDocument);

        WSSSecurityProperties inSecurityProperties = new WSSSecurityProperties();
        inSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
        inSecurityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
        inSecurityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());

        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);
        inSecurityProperties.addInputProcessor(new PolicyInputProcessor(policyEnforcer, inSecurityProperties));

        Document document = doInboundSecurity(inSecurityProperties, new ByteArrayInputStream(baos.toByteArray()), policyEnforcer);

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
                        "                <sp:AsymmetricBinding>\n" +
                        "                    <wsp:Policy>\n" +
                        "                        <sp:InitiatorToken>\n" +
                        "                            <wsp:Policy>\n" +
                        "                                <sp:X509Token IncludeToken=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702/IncludeToken/AlwaysToRecipient\">\n" +
                        "                                    <sp:IssuerName>CN=transmitter,OU=swssf,C=CH</sp:IssuerName>\n" +
                        "                                    <wsp:Policy>\n" +
                        "                                        <sp:WssX509V3Token11/>\n" +
                        "                                    </wsp:Policy>\n" +
                        "                                </sp:X509Token>\n" +
                        "                            </wsp:Policy>\n" +
                        "                        </sp:InitiatorToken>\n" +
                        "                        <sp:RecipientToken>\n" +
                        "                            <wsp:Policy>\n" +
                        "                              <sp:X509Token IncludeToken=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702/IncludeToken/AlwaysToRecipient\">\n" +
                        "                                  <sp:IssuerName>CN=receiver,OU=swssf,C=CH</sp:IssuerName>\n" +
                        "                                  <wsp:Policy>\n" +
                        "                                      <sp:WssX509V3Token11/>\n" +
                        "                                  </wsp:Policy>\n" +
                        "                              </sp:X509Token>\n" +
                        "                            </wsp:Policy>\n" +
                        "                         </sp:RecipientToken>\n" +
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
                        "                </sp:AsymmetricBinding>\n" +
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

        outSecurityProperties.addSignaturePart(new SecurePart(WSSConstants.TAG_wsu_Timestamp, SecurePart.Modifier.Element));
        outSecurityProperties.addSignaturePart(new SecurePart(WSSConstants.TAG_soap11_Body, SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_wsu_Created, SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_wsu_Expires, SecurePart.Modifier.Content));
        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_soap11_Body, SecurePart.Modifier.Content));
        WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.TIMESTAMP, WSSConstants.SIGNATURE, WSSConstants.ENCRYPT};
        outSecurityProperties.setOutAction(actions);

        InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
        ByteArrayOutputStream baos = doOutboundSecurity(outSecurityProperties, sourceDocument);

        WSSSecurityProperties inSecurityProperties = new WSSSecurityProperties();
        inSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
        inSecurityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
        inSecurityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());

        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);
        inSecurityProperties.addInputProcessor(new PolicyInputProcessor(policyEnforcer, inSecurityProperties));

        try {
            Document document = doInboundSecurity(inSecurityProperties, new ByteArrayInputStream(baos.toByteArray()), policyEnforcer);

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
                    "\torg.swssf.policy.PolicyViolationException: \n" +
                    "Timestamp must not be present");
        }
    }

    @Test
    public void testIncludeTimestampAndSignedUsernameSupportingTokenPolicy() throws Exception {

        String policyString =
                "<wsp:ExactlyOne xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\" " +
                        "xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\">\n" +
                        "            <wsp:All>\n" +
                        "                <sp:AsymmetricBinding>\n" +
                        "                    <wsp:Policy>\n" +
                        "                        <sp:InitiatorToken>\n" +
                        "                            <wsp:Policy>\n" +
                        "                                <sp:X509Token IncludeToken=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702/IncludeToken/AlwaysToRecipient\">\n" +
                        "                                    <sp:IssuerName>CN=transmitter,OU=swssf,C=CH</sp:IssuerName>\n" +
                        "                                    <wsp:Policy>\n" +
                        "                                        <sp:WssX509V3Token11/>\n" +
                        "                                    </wsp:Policy>\n" +
                        "                                </sp:X509Token>\n" +
                        "                            </wsp:Policy>\n" +
                        "                        </sp:InitiatorToken>\n" +
                        "                        <sp:RecipientToken>\n" +
                        "                            <wsp:Policy>\n" +
                        "                              <sp:X509Token IncludeToken=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702/IncludeToken/AlwaysToRecipient\">\n" +
                        "                                  <sp:IssuerName>CN=receiver,OU=swssf,C=CH</sp:IssuerName>\n" +
                        "                                  <wsp:Policy>\n" +
                        "                                      <sp:WssX509V3Token11/>\n" +
                        "                                  </wsp:Policy>\n" +
                        "                              </sp:X509Token>\n" +
                        "                            </wsp:Policy>\n" +
                        "                         </sp:RecipientToken>\n" +
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
                        "                </sp:AsymmetricBinding>\n" +
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

        outSecurityProperties.addSignaturePart(new SecurePart(WSSConstants.TAG_wsu_Timestamp, SecurePart.Modifier.Element));
        outSecurityProperties.addSignaturePart(new SecurePart(WSSConstants.TAG_soap11_Body, SecurePart.Modifier.Element));
        outSecurityProperties.addSignaturePart(new SecurePart(WSSConstants.TAG_wsse_UsernameToken, SecurePart.Modifier.Element));
        //outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_wsu_Timestamp, SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_wsu_Created, SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_wsu_Expires, SecurePart.Modifier.Content));
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
        inSecurityProperties.addInputProcessor(new PolicyInputProcessor(policyEnforcer, inSecurityProperties));

        Document document = doInboundSecurity(inSecurityProperties, new ByteArrayInputStream(baos.toByteArray()), policyEnforcer);

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
                        "                <sp:AsymmetricBinding>\n" +
                        "                    <wsp:Policy>\n" +
                        "                        <sp:InitiatorToken>\n" +
                        "                            <wsp:Policy>\n" +
                        "                                <sp:X509Token IncludeToken=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702/IncludeToken/AlwaysToRecipient\">\n" +
                        "                                    <sp:IssuerName>CN=transmitter,OU=swssf,C=CH</sp:IssuerName>\n" +
                        "                                    <wsp:Policy>\n" +
                        "                                        <sp:WssX509V3Token11/>\n" +
                        "                                    </wsp:Policy>\n" +
                        "                                </sp:X509Token>\n" +
                        "                            </wsp:Policy>\n" +
                        "                        </sp:InitiatorToken>\n" +
                        "                        <sp:RecipientToken>\n" +
                        "                            <wsp:Policy>\n" +
                        "                              <sp:X509Token IncludeToken=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702/IncludeToken/AlwaysToRecipient\">\n" +
                        "                                  <sp:IssuerName>CN=receiver,OU=swssf,C=CH</sp:IssuerName>\n" +
                        "                                  <wsp:Policy>\n" +
                        "                                      <sp:WssX509V3Token11/>\n" +
                        "                                  </wsp:Policy>\n" +
                        "                              </sp:X509Token>\n" +
                        "                            </wsp:Policy>\n" +
                        "                         </sp:RecipientToken>\n" +
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
                        "                </sp:AsymmetricBinding>\n" +
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

        //outSecurityProperties.addSignaturePart(new SecurePart(WSSConstants.TAG_wsu_Timestamp, SecurePart.Modifier.Element));
        outSecurityProperties.addSignaturePart(new SecurePart(WSSConstants.TAG_soap11_Body, SecurePart.Modifier.Element));
        //outSecurityProperties.addSignaturePart(new SecurePart(WSSConstants.TAG_wsse_UsernameToken, SecurePart.Modifier.Element));
        //outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_wsu_Timestamp, SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_wsu_Created, SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_wsu_Expires, SecurePart.Modifier.Content));
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
        inSecurityProperties.addInputProcessor(new PolicyInputProcessor(policyEnforcer, inSecurityProperties));

        try {
            Document document = doInboundSecurity(inSecurityProperties, new ByteArrayInputStream(baos.toByteArray()), policyEnforcer);

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
                    "\torg.swssf.policy.PolicyViolationException: \n" +
                    "Element /{http://schemas.xmlsoap.org/soap/envelope/}Envelope/{http://schemas.xmlsoap.org/soap/envelope/}Header/{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd}Security/{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd}Timestamp must be signed");
        }
    }

    @Test
    public void testIncludeTimestampAndSignedUsernameSupportingTokenPolicyNegativeTest2() throws Exception {

        String policyString =
                "<wsp:ExactlyOne xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\" " +
                        "xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\">\n" +
                        "            <wsp:All>\n" +
                        "                <sp:AsymmetricBinding>\n" +
                        "                    <wsp:Policy>\n" +
                        "                        <sp:InitiatorToken>\n" +
                        "                            <wsp:Policy>\n" +
                        "                                <sp:X509Token IncludeToken=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702/IncludeToken/AlwaysToRecipient\">\n" +
                        "                                    <sp:IssuerName>CN=transmitter,OU=swssf,C=CH</sp:IssuerName>\n" +
                        "                                    <wsp:Policy>\n" +
                        "                                        <sp:WssX509V3Token11/>\n" +
                        "                                    </wsp:Policy>\n" +
                        "                                </sp:X509Token>\n" +
                        "                            </wsp:Policy>\n" +
                        "                        </sp:InitiatorToken>\n" +
                        "                        <sp:RecipientToken>\n" +
                        "                            <wsp:Policy>\n" +
                        "                              <sp:X509Token IncludeToken=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702/IncludeToken/AlwaysToRecipient\">\n" +
                        "                                  <sp:IssuerName>CN=receiver,OU=swssf,C=CH</sp:IssuerName>\n" +
                        "                                  <wsp:Policy>\n" +
                        "                                      <sp:WssX509V3Token11/>\n" +
                        "                                  </wsp:Policy>\n" +
                        "                              </sp:X509Token>\n" +
                        "                            </wsp:Policy>\n" +
                        "                         </sp:RecipientToken>\n" +
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
                        "                </sp:AsymmetricBinding>\n" +
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

        outSecurityProperties.addSignaturePart(new SecurePart(WSSConstants.TAG_wsu_Timestamp, SecurePart.Modifier.Element));
        outSecurityProperties.addSignaturePart(new SecurePart(WSSConstants.TAG_soap11_Body, SecurePart.Modifier.Element));
        //outSecurityProperties.addSignaturePart(new SecurePart(WSSConstants.TAG_wsse_UsernameToken, SecurePart.Modifier.Element));
        //outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_wsu_Timestamp, SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_wsu_Created, SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_wsu_Expires, SecurePart.Modifier.Content));
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
        inSecurityProperties.addInputProcessor(new PolicyInputProcessor(policyEnforcer, inSecurityProperties));

        try {
            Document document = doInboundSecurity(inSecurityProperties, new ByteArrayInputStream(baos.toByteArray()), policyEnforcer);

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
                    "\torg.apache.ws.secpolicy.WSSPolicyException: Assertion {http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702}UsernameToken not satisfied");
        }
    }

    @Test
    public void testIncludeTimestampAndProtectionOrderEncryptBeforeSignAndSignedUsernameSupportingTokenPolicyTest() throws Exception {

        String policyString =
                "<wsp:ExactlyOne xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\" " +
                        "xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\">\n" +
                        "            <wsp:All>\n" +
                        "                <sp:AsymmetricBinding>\n" +
                        "                    <wsp:Policy>\n" +
                        "                        <sp:InitiatorToken>\n" +
                        "                            <wsp:Policy>\n" +
                        "                                <sp:X509Token IncludeToken=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702/IncludeToken/AlwaysToRecipient\">\n" +
                        "                                    <sp:IssuerName>CN=transmitter,OU=swssf,C=CH</sp:IssuerName>\n" +
                        "                                    <wsp:Policy>\n" +
                        "                                        <sp:WssX509V3Token11/>\n" +
                        "                                    </wsp:Policy>\n" +
                        "                                </sp:X509Token>\n" +
                        "                            </wsp:Policy>\n" +
                        "                        </sp:InitiatorToken>\n" +
                        "                        <sp:RecipientToken>\n" +
                        "                            <wsp:Policy>\n" +
                        "                              <sp:X509Token IncludeToken=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702/IncludeToken/AlwaysToRecipient\">\n" +
                        "                                  <sp:IssuerName>CN=receiver,OU=swssf,C=CH</sp:IssuerName>\n" +
                        "                                  <wsp:Policy>\n" +
                        "                                      <sp:WssX509V3Token11/>\n" +
                        "                                  </wsp:Policy>\n" +
                        "                              </sp:X509Token>\n" +
                        "                            </wsp:Policy>\n" +
                        "                         </sp:RecipientToken>\n" +
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
                        "                        <sp:EncryptBeforeSigning/>\n" +
                        "                    </wsp:Policy>\n" +
                        "                </sp:AsymmetricBinding>\n" +
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

        outSecurityProperties.addSignaturePart(new SecurePart(WSSConstants.TAG_wsu_Timestamp, SecurePart.Modifier.Element));
        outSecurityProperties.addSignaturePart(new SecurePart(WSSConstants.TAG_soap11_Body, SecurePart.Modifier.Element));
        outSecurityProperties.addSignaturePart(new SecurePart(WSSConstants.TAG_wsse_UsernameToken, SecurePart.Modifier.Element));
        //outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_wsu_Timestamp, SecurePart.Modifier.Element));
        //outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_wsu_Created, SecurePart.Modifier.Element));
        //outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_wsu_Expires, SecurePart.Modifier.Content));
        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_soap11_Body, SecurePart.Modifier.Content));
        WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.USERNAMETOKEN, WSSConstants.TIMESTAMP, WSSConstants.ENCRYPT, WSSConstants.SIGNATURE};
        outSecurityProperties.setOutAction(actions);

        InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
        ByteArrayOutputStream baos = doOutboundSecurity(outSecurityProperties, sourceDocument);

        WSSSecurityProperties inSecurityProperties = new WSSSecurityProperties();
        inSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
        inSecurityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
        inSecurityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());

        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);
        inSecurityProperties.addInputProcessor(new PolicyInputProcessor(policyEnforcer, inSecurityProperties));

        Document document = doInboundSecurity(inSecurityProperties, new ByteArrayInputStream(baos.toByteArray()), policyEnforcer);

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
    public void testSignatureAlgorithmSuiteNegative() throws Exception {

        String policyString =
                "<wsp:ExactlyOne xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\" " +
                        "xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\">\n" +
                        "            <wsp:All>\n" +
                        "                <sp:AsymmetricBinding>\n" +
                        "                    <wsp:Policy>\n" +
                        "                        <sp:InitiatorToken>\n" +
                        "                            <wsp:Policy>\n" +
                        "                                <sp:X509Token IncludeToken=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702/IncludeToken/AlwaysToRecipient\">\n" +
                        "                                    <sp:IssuerName>CN=transmitter,OU=swssf,C=CH</sp:IssuerName>\n" +
                        "                                    <wsp:Policy>\n" +
                        "                                        <sp:WssX509V3Token11/>\n" +
                        "                                    </wsp:Policy>\n" +
                        "                                </sp:X509Token>\n" +
                        "                            </wsp:Policy>\n" +
                        "                        </sp:InitiatorToken>\n" +
                        "                        <sp:RecipientToken>\n" +
                        "                            <wsp:Policy>\n" +
                        "                              <sp:X509Token IncludeToken=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702/IncludeToken/AlwaysToRecipient\">\n" +
                        "                                  <sp:IssuerName>CN=receiver,OU=swssf,C=CH</sp:IssuerName>\n" +
                        "                                  <wsp:Policy>\n" +
                        "                                      <sp:WssX509V3Token11/>\n" +
                        "                                  </wsp:Policy>\n" +
                        "                              </sp:X509Token>\n" +
                        "                            </wsp:Policy>\n" +
                        "                         </sp:RecipientToken>\n" +
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
                        "                        <sp:ProtectTokens/>\n" +
                        "                    </wsp:Policy>\n" +
                        "                </sp:AsymmetricBinding>\n" +
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

        outSecurityProperties.addSignaturePart(new SecurePart(WSSConstants.TAG_wsu_Timestamp, SecurePart.Modifier.Element));
        outSecurityProperties.addSignaturePart(new SecurePart(WSSConstants.TAG_soap11_Body, SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_wsu_Created, SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_wsu_Expires, SecurePart.Modifier.Content));
        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_soap11_Body, SecurePart.Modifier.Content));
        WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.TIMESTAMP, WSSConstants.SIGNATURE, WSSConstants.ENCRYPT};
        outSecurityProperties.setOutAction(actions);

        InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
        ByteArrayOutputStream baos = doOutboundSecurity(outSecurityProperties, sourceDocument);

        WSSSecurityProperties inSecurityProperties = new WSSSecurityProperties();
        inSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
        inSecurityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
        inSecurityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
        inSecurityProperties.addIgnoreBSPRule(WSSConstants.BSPRule.R5421);
        inSecurityProperties.addIgnoreBSPRule(WSSConstants.BSPRule.R5420);

        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);
        inSecurityProperties.addInputProcessor(new PolicyInputProcessor(policyEnforcer, inSecurityProperties));

        try {
            Document document = doInboundSecurity(inSecurityProperties, new ByteArrayInputStream(baos.toByteArray()), policyEnforcer);

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
                    "\torg.swssf.policy.PolicyViolationException: \n" +
                    "Asymmetric algorithm http://www.w3.org/2001/04/xmldsig-more#rsa-sha512 does not meet policy");
        }
    }

    @Test
    public void testC14NAlgorithmSuiteNegative() throws Exception {

        String policyString =
                "<wsp:ExactlyOne xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\" " +
                        "xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\">\n" +
                        "            <wsp:All>\n" +
                        "                <sp:AsymmetricBinding>\n" +
                        "                    <wsp:Policy>\n" +
                        "                        <sp:InitiatorToken>\n" +
                        "                            <wsp:Policy>\n" +
                        "                                <sp:X509Token IncludeToken=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702/IncludeToken/AlwaysToRecipient\">\n" +
                        "                                    <sp:IssuerName>CN=transmitter,OU=swssf,C=CH</sp:IssuerName>\n" +
                        "                                    <wsp:Policy>\n" +
                        "                                        <sp:WssX509V3Token11/>\n" +
                        "                                    </wsp:Policy>\n" +
                        "                                </sp:X509Token>\n" +
                        "                            </wsp:Policy>\n" +
                        "                        </sp:InitiatorToken>\n" +
                        "                        <sp:RecipientToken>\n" +
                        "                            <wsp:Policy>\n" +
                        "                              <sp:X509Token IncludeToken=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702/IncludeToken/AlwaysToRecipient\">\n" +
                        "                                  <sp:IssuerName>CN=receiver,OU=swssf,C=CH</sp:IssuerName>\n" +
                        "                                  <wsp:Policy>\n" +
                        "                                      <sp:WssX509V3Token11/>\n" +
                        "                                  </wsp:Policy>\n" +
                        "                              </sp:X509Token>\n" +
                        "                            </wsp:Policy>\n" +
                        "                         </sp:RecipientToken>\n" +
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
                        "                        <sp:ProtectTokens/>\n" +
                        "                    </wsp:Policy>\n" +
                        "                </sp:AsymmetricBinding>\n" +
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

        outSecurityProperties.addSignaturePart(new SecurePart(WSSConstants.TAG_wsu_Timestamp, SecurePart.Modifier.Element));
        outSecurityProperties.addSignaturePart(new SecurePart(WSSConstants.TAG_soap11_Body, SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_wsu_Created, SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_wsu_Expires, SecurePart.Modifier.Content));
        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_soap11_Body, SecurePart.Modifier.Content));
        WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.TIMESTAMP, WSSConstants.SIGNATURE, WSSConstants.ENCRYPT};
        outSecurityProperties.setOutAction(actions);

        InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
        ByteArrayOutputStream baos = doOutboundSecurity(outSecurityProperties, sourceDocument);

        WSSSecurityProperties inSecurityProperties = new WSSSecurityProperties();
        inSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
        inSecurityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
        inSecurityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
        inSecurityProperties.addIgnoreBSPRule(WSSConstants.BSPRule.R5404);
        inSecurityProperties.addIgnoreBSPRule(WSSConstants.BSPRule.R5423);
        inSecurityProperties.addIgnoreBSPRule(WSSConstants.BSPRule.R5412);

        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);
        inSecurityProperties.addInputProcessor(new PolicyInputProcessor(policyEnforcer, inSecurityProperties));

        try {
            Document document = doInboundSecurity(inSecurityProperties, new ByteArrayInputStream(baos.toByteArray()), policyEnforcer);

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
                    "\torg.swssf.policy.PolicyViolationException: \n" +
                    "C14N algorithm http://www.w3.org/2006/12/xml-c14n11 does not meet policy");
        }
    }

    @Test
    public void testSignatureDigestAlgorithmSuiteNegative() throws Exception {

        String policyString =
                "<wsp:ExactlyOne xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\" " +
                        "xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\">\n" +
                        "            <wsp:All>\n" +
                        "                <sp:AsymmetricBinding>\n" +
                        "                    <wsp:Policy>\n" +
                        "                        <sp:InitiatorToken>\n" +
                        "                            <wsp:Policy>\n" +
                        "                                <sp:X509Token IncludeToken=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702/IncludeToken/AlwaysToRecipient\">\n" +
                        "                                    <sp:IssuerName>CN=transmitter,OU=swssf,C=CH</sp:IssuerName>\n" +
                        "                                    <wsp:Policy>\n" +
                        "                                        <sp:WssX509V3Token11/>\n" +
                        "                                    </wsp:Policy>\n" +
                        "                                </sp:X509Token>\n" +
                        "                            </wsp:Policy>\n" +
                        "                        </sp:InitiatorToken>\n" +
                        "                        <sp:RecipientToken>\n" +
                        "                            <wsp:Policy>\n" +
                        "                              <sp:X509Token IncludeToken=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702/IncludeToken/AlwaysToRecipient\">\n" +
                        "                                  <sp:IssuerName>CN=receiver,OU=swssf,C=CH</sp:IssuerName>\n" +
                        "                                  <wsp:Policy>\n" +
                        "                                      <sp:WssX509V3Token11/>\n" +
                        "                                  </wsp:Policy>\n" +
                        "                              </sp:X509Token>\n" +
                        "                            </wsp:Policy>\n" +
                        "                         </sp:RecipientToken>\n" +
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
                        "                        <sp:ProtectTokens/>\n" +
                        "                    </wsp:Policy>\n" +
                        "                </sp:AsymmetricBinding>\n" +
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
        outSecurityProperties.setSignatureDigestAlgorithm("http://www.w3.org/2001/04/xmldsig-more#md5");

        outSecurityProperties.addSignaturePart(new SecurePart(WSSConstants.TAG_wsu_Timestamp, SecurePart.Modifier.Element));
        outSecurityProperties.addSignaturePart(new SecurePart(WSSConstants.TAG_soap11_Body, SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_wsu_Created, SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_wsu_Expires, SecurePart.Modifier.Content));
        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_soap11_Body, SecurePart.Modifier.Content));
        WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.TIMESTAMP, WSSConstants.SIGNATURE, WSSConstants.ENCRYPT};
        outSecurityProperties.setOutAction(actions);

        InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
        ByteArrayOutputStream baos = doOutboundSecurity(outSecurityProperties, sourceDocument);

        WSSSecurityProperties inSecurityProperties = new WSSSecurityProperties();
        inSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
        inSecurityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
        inSecurityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
        inSecurityProperties.addIgnoreBSPRule(WSSConstants.BSPRule.R5420);

        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);
        inSecurityProperties.addInputProcessor(new PolicyInputProcessor(policyEnforcer, inSecurityProperties));

        try {
            Document document = doInboundSecurity(inSecurityProperties, new ByteArrayInputStream(baos.toByteArray()), policyEnforcer);

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
                    "\torg.swssf.policy.PolicyViolationException: \n" +
                    "Digest algorithm http://www.w3.org/2001/04/xmldsig-more#md5 does not meet policy");
        }
    }

    @Test
    public void testEncryptionAlgorithmSuiteNegative() throws Exception {

        String policyString =
                "<wsp:ExactlyOne xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\" " +
                        "xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\">\n" +
                        "            <wsp:All>\n" +
                        "                <sp:AsymmetricBinding>\n" +
                        "                    <wsp:Policy>\n" +
                        "                        <sp:InitiatorToken>\n" +
                        "                            <wsp:Policy>\n" +
                        "                                <sp:X509Token IncludeToken=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702/IncludeToken/AlwaysToRecipient\">\n" +
                        "                                    <sp:IssuerName>CN=transmitter,OU=swssf,C=CH</sp:IssuerName>\n" +
                        "                                    <wsp:Policy>\n" +
                        "                                        <sp:WssX509V3Token11/>\n" +
                        "                                    </wsp:Policy>\n" +
                        "                                </sp:X509Token>\n" +
                        "                            </wsp:Policy>\n" +
                        "                        </sp:InitiatorToken>\n" +
                        "                        <sp:RecipientToken>\n" +
                        "                            <wsp:Policy>\n" +
                        "                              <sp:X509Token IncludeToken=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702/IncludeToken/AlwaysToRecipient\">\n" +
                        "                                  <sp:IssuerName>CN=receiver,OU=swssf,C=CH</sp:IssuerName>\n" +
                        "                                  <wsp:Policy>\n" +
                        "                                      <sp:WssX509V3Token11/>\n" +
                        "                                  </wsp:Policy>\n" +
                        "                              </sp:X509Token>\n" +
                        "                            </wsp:Policy>\n" +
                        "                         </sp:RecipientToken>\n" +
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
                        "                        <sp:ProtectTokens/>\n" +
                        "                    </wsp:Policy>\n" +
                        "                </sp:AsymmetricBinding>\n" +
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

        outSecurityProperties.addSignaturePart(new SecurePart(WSSConstants.TAG_wsu_Timestamp, SecurePart.Modifier.Element));
        outSecurityProperties.addSignaturePart(new SecurePart(WSSConstants.TAG_soap11_Body, SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_wsu_Created, SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_wsu_Expires, SecurePart.Modifier.Content));
        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_soap11_Body, SecurePart.Modifier.Content));
        WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.TIMESTAMP, WSSConstants.SIGNATURE, WSSConstants.ENCRYPT};
        outSecurityProperties.setOutAction(actions);

        InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
        ByteArrayOutputStream baos = doOutboundSecurity(outSecurityProperties, sourceDocument);

        WSSSecurityProperties inSecurityProperties = new WSSSecurityProperties();
        inSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
        inSecurityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
        inSecurityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());

        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);
        inSecurityProperties.addInputProcessor(new PolicyInputProcessor(policyEnforcer, inSecurityProperties));

        try {
            Document document = doInboundSecurity(inSecurityProperties, new ByteArrayInputStream(baos.toByteArray()), policyEnforcer);

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
                    "\torg.swssf.policy.PolicyViolationException: \n" +
                    "Encryption algorithm http://www.w3.org/2001/04/xmlenc#tripledes-cbc does not meet policy\n" +
                    "Symmetric encryption algorithm key length 192 does not meet policy");
        }
    }

    @Test
    public void testSignatureProtectionPolicy() throws Exception {

        String policyString =
                "<wsp:ExactlyOne xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\" " +
                        "xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\">\n" +
                        "            <wsp:All>\n" +
                        "                <sp:AsymmetricBinding>\n" +
                        "                    <wsp:Policy>\n" +
                        "                        <sp:InitiatorToken>\n" +
                        "                            <wsp:Policy>\n" +
                        "                                <sp:X509Token IncludeToken=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702/IncludeToken/AlwaysToRecipient\">\n" +
                        "                                    <sp:IssuerName>CN=transmitter,OU=swssf,C=CH</sp:IssuerName>\n" +
                        "                                    <wsp:Policy>\n" +
                        "                                        <sp:WssX509V3Token11/>\n" +
                        "                                    </wsp:Policy>\n" +
                        "                                </sp:X509Token>\n" +
                        "                            </wsp:Policy>\n" +
                        "                        </sp:InitiatorToken>\n" +
                        "                        <sp:RecipientToken>\n" +
                        "                            <wsp:Policy>\n" +
                        "                              <sp:X509Token IncludeToken=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702/IncludeToken/AlwaysToRecipient\">\n" +
                        "                                  <sp:IssuerName>CN=receiver,OU=swssf,C=CH</sp:IssuerName>\n" +
                        "                                  <wsp:Policy>\n" +
                        "                                      <sp:WssX509V3Token11/>\n" +
                        "                                  </wsp:Policy>\n" +
                        "                              </sp:X509Token>\n" +
                        "                            </wsp:Policy>\n" +
                        "                         </sp:RecipientToken>\n" +
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
                        "                        <sp:EncryptSignature/>\n" +
                        "                    </wsp:Policy>\n" +
                        "                </sp:AsymmetricBinding>\n" +
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

        outSecurityProperties.addSignaturePart(new SecurePart(WSSConstants.TAG_wsu_Timestamp, SecurePart.Modifier.Element));
        outSecurityProperties.addSignaturePart(new SecurePart(WSSConstants.TAG_soap11_Body, SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_dsig_Signature, SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_wsu_Created, SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_wsu_Expires, SecurePart.Modifier.Content));
        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_soap11_Body, SecurePart.Modifier.Content));
        WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.TIMESTAMP, WSSConstants.SIGNATURE, WSSConstants.ENCRYPT};
        outSecurityProperties.setOutAction(actions);

        InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
        ByteArrayOutputStream baos = doOutboundSecurity(outSecurityProperties, sourceDocument);

        WSSSecurityProperties inSecurityProperties = new WSSSecurityProperties();
        inSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
        inSecurityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
        inSecurityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());

        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);
        inSecurityProperties.addInputProcessor(new PolicyInputProcessor(policyEnforcer, inSecurityProperties));

        Document document = doInboundSecurity(inSecurityProperties, new ByteArrayInputStream(baos.toByteArray()), policyEnforcer);

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
    public void testSignatureProtectionPolicyNegative1() throws Exception {

        String policyString =
                "<wsp:ExactlyOne xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\" " +
                        "xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\">\n" +
                        "            <wsp:All>\n" +
                        "                <sp:AsymmetricBinding>\n" +
                        "                    <wsp:Policy>\n" +
                        "                        <sp:InitiatorToken>\n" +
                        "                            <wsp:Policy>\n" +
                        "                                <sp:X509Token IncludeToken=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702/IncludeToken/AlwaysToRecipient\">\n" +
                        "                                    <sp:IssuerName>CN=transmitter,OU=swssf,C=CH</sp:IssuerName>\n" +
                        "                                    <wsp:Policy>\n" +
                        "                                        <sp:WssX509V3Token11/>\n" +
                        "                                    </wsp:Policy>\n" +
                        "                                </sp:X509Token>\n" +
                        "                            </wsp:Policy>\n" +
                        "                        </sp:InitiatorToken>\n" +
                        "                        <sp:RecipientToken>\n" +
                        "                            <wsp:Policy>\n" +
                        "                              <sp:X509Token IncludeToken=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702/IncludeToken/AlwaysToRecipient\">\n" +
                        "                                  <sp:IssuerName>CN=receiver,OU=swssf,C=CH</sp:IssuerName>\n" +
                        "                                  <wsp:Policy>\n" +
                        "                                      <sp:WssX509V3Token11/>\n" +
                        "                                  </wsp:Policy>\n" +
                        "                              </sp:X509Token>\n" +
                        "                            </wsp:Policy>\n" +
                        "                         </sp:RecipientToken>\n" +
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
                        "                        <sp:EncryptSignature/>\n" +
                        "                    </wsp:Policy>\n" +
                        "                </sp:AsymmetricBinding>\n" +
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

        outSecurityProperties.addSignaturePart(new SecurePart(WSSConstants.TAG_wsu_Timestamp, SecurePart.Modifier.Element));
        outSecurityProperties.addSignaturePart(new SecurePart(WSSConstants.TAG_soap11_Body, SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_wsu_Created, SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_wsu_Expires, SecurePart.Modifier.Content));
        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_soap11_Body, SecurePart.Modifier.Content));
        WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.TIMESTAMP, WSSConstants.SIGNATURE, WSSConstants.ENCRYPT};
        outSecurityProperties.setOutAction(actions);

        InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
        ByteArrayOutputStream baos = doOutboundSecurity(outSecurityProperties, sourceDocument);

        WSSSecurityProperties inSecurityProperties = new WSSSecurityProperties();
        inSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
        inSecurityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
        inSecurityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());

        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);
        inSecurityProperties.addInputProcessor(new PolicyInputProcessor(policyEnforcer, inSecurityProperties));

        try {
            Document document = doInboundSecurity(inSecurityProperties, new ByteArrayInputStream(baos.toByteArray()), policyEnforcer);

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
                    "\torg.swssf.policy.PolicyViolationException: \n" +
                    "Element /{http://schemas.xmlsoap.org/soap/envelope/}Envelope/{http://schemas.xmlsoap.org/soap/envelope/}Header/{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd}Security/{http://www.w3.org/2000/09/xmldsig#}Signature must be encrypted");
        }
    }

    @Test
    public void testSignatureProtectionPolicyNegative2() throws Exception {

        String policyString =
                "<wsp:ExactlyOne xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\" " +
                        "xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\">\n" +
                        "            <wsp:All>\n" +
                        "                <sp:AsymmetricBinding>\n" +
                        "                    <wsp:Policy>\n" +
                        "                        <sp:InitiatorToken>\n" +
                        "                            <wsp:Policy>\n" +
                        "                                <sp:X509Token IncludeToken=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702/IncludeToken/AlwaysToRecipient\">\n" +
                        "                                    <sp:IssuerName>CN=transmitter,OU=swssf,C=CH</sp:IssuerName>\n" +
                        "                                    <wsp:Policy>\n" +
                        "                                        <sp:WssX509V3Token11/>\n" +
                        "                                    </wsp:Policy>\n" +
                        "                                </sp:X509Token>\n" +
                        "                            </wsp:Policy>\n" +
                        "                        </sp:InitiatorToken>\n" +
                        "                        <sp:RecipientToken>\n" +
                        "                            <wsp:Policy>\n" +
                        "                              <sp:X509Token IncludeToken=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702/IncludeToken/AlwaysToRecipient\">\n" +
                        "                                  <sp:IssuerName>CN=receiver,OU=swssf,C=CH</sp:IssuerName>\n" +
                        "                                  <wsp:Policy>\n" +
                        "                                      <sp:WssX509V3Token11/>\n" +
                        "                                  </wsp:Policy>\n" +
                        "                              </sp:X509Token>\n" +
                        "                            </wsp:Policy>\n" +
                        "                         </sp:RecipientToken>\n" +
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
                        "                </sp:AsymmetricBinding>\n" +
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

        outSecurityProperties.addSignaturePart(new SecurePart(WSSConstants.TAG_wsu_Timestamp, SecurePart.Modifier.Element));
        outSecurityProperties.addSignaturePart(new SecurePart(WSSConstants.TAG_soap11_Body, SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_dsig_Signature, SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_wsu_Created, SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_wsu_Expires, SecurePart.Modifier.Content));
        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_soap11_Body, SecurePart.Modifier.Content));
        WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.TIMESTAMP, WSSConstants.SIGNATURE, WSSConstants.ENCRYPT};
        outSecurityProperties.setOutAction(actions);

        InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
        ByteArrayOutputStream baos = doOutboundSecurity(outSecurityProperties, sourceDocument);

        WSSSecurityProperties inSecurityProperties = new WSSSecurityProperties();
        inSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
        inSecurityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
        inSecurityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());

        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);
        inSecurityProperties.addInputProcessor(new PolicyInputProcessor(policyEnforcer, inSecurityProperties));

        try {
            Document document = doInboundSecurity(inSecurityProperties, new ByteArrayInputStream(baos.toByteArray()), policyEnforcer);

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
                    "\torg.swssf.policy.PolicyViolationException: \n" +
                    "Element /{http://schemas.xmlsoap.org/soap/envelope/}Envelope/{http://schemas.xmlsoap.org/soap/envelope/}Header/{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd}Security/{http://www.w3.org/2000/09/xmldsig#}Signature must not be encrypted");
        }
    }

    @Test
    public void testEntireHeaderAndBodySignature() throws Exception {

        String policyString =
                "<wsp:ExactlyOne xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\" " +
                        "xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\">\n" +
                        "            <wsp:All>\n" +
                        "                <sp:AsymmetricBinding>\n" +
                        "                    <wsp:Policy>\n" +
                        "                        <sp:InitiatorToken>\n" +
                        "                            <wsp:Policy>\n" +
                        "                                <sp:X509Token IncludeToken=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702/IncludeToken/AlwaysToRecipient\">\n" +
                        "                                    <sp:IssuerName>CN=transmitter,OU=swssf,C=CH</sp:IssuerName>\n" +
                        "                                    <wsp:Policy>\n" +
                        "                                        <sp:WssX509V3Token11/>\n" +
                        "                                    </wsp:Policy>\n" +
                        "                                </sp:X509Token>\n" +
                        "                            </wsp:Policy>\n" +
                        "                        </sp:InitiatorToken>\n" +
                        "                        <sp:RecipientToken>\n" +
                        "                            <wsp:Policy>\n" +
                        "                              <sp:X509Token IncludeToken=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702/IncludeToken/AlwaysToRecipient\">\n" +
                        "                                  <sp:IssuerName>CN=receiver,OU=swssf,C=CH</sp:IssuerName>\n" +
                        "                                  <wsp:Policy>\n" +
                        "                                      <sp:WssX509V3Token11/>\n" +
                        "                                  </wsp:Policy>\n" +
                        "                              </sp:X509Token>\n" +
                        "                            </wsp:Policy>\n" +
                        "                         </sp:RecipientToken>\n" +
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
                        "                        <sp:OnlySignEntireHeadersAndBody/>\n" +
                        "                    </wsp:Policy>\n" +
                        "                </sp:AsymmetricBinding>\n" +
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
                        "            </wsp:All>\n" +
                        "        </wsp:ExactlyOne>";

        WSSSecurityProperties outSecurityProperties = new WSSSecurityProperties();
        outSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
        outSecurityProperties.setEncryptionUser("receiver");
        outSecurityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
        outSecurityProperties.setSignatureUser("transmitter");
        outSecurityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());

        outSecurityProperties.addSignaturePart(new SecurePart(WSSConstants.TAG_wsu_Timestamp, SecurePart.Modifier.Element));
        outSecurityProperties.addSignaturePart(new SecurePart(WSSConstants.TAG_soap11_Body, SecurePart.Modifier.Element));
        outSecurityProperties.addSignaturePart(new SecurePart(new QName("http://schemas.xmlsoap.org/wsdl/", "definitions"), SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_wsu_Created, SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_wsu_Expires, SecurePart.Modifier.Content));
        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_soap11_Body, SecurePart.Modifier.Content));
        WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.TIMESTAMP, WSSConstants.SIGNATURE, WSSConstants.ENCRYPT};
        outSecurityProperties.setOutAction(actions);

        InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
        ByteArrayOutputStream baos = doOutboundSecurity(outSecurityProperties, sourceDocument);

        WSSSecurityProperties inSecurityProperties = new WSSSecurityProperties();
        inSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
        inSecurityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
        inSecurityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());

        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);
        inSecurityProperties.addInputProcessor(new PolicyInputProcessor(policyEnforcer, inSecurityProperties));

        Document document = doInboundSecurity(inSecurityProperties, new ByteArrayInputStream(baos.toByteArray()), policyEnforcer);

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
    public void testEntireHeaderAndBodySignatureNegative() throws Exception {

        String policyString =
                "<wsp:ExactlyOne xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\" " +
                        "xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\">\n" +
                        "            <wsp:All>\n" +
                        "                <sp:AsymmetricBinding>\n" +
                        "                    <wsp:Policy>\n" +
                        "                        <sp:InitiatorToken>\n" +
                        "                            <wsp:Policy>\n" +
                        "                                <sp:X509Token IncludeToken=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702/IncludeToken/AlwaysToRecipient\">\n" +
                        "                                    <sp:IssuerName>CN=transmitter,OU=swssf,C=CH</sp:IssuerName>\n" +
                        "                                    <wsp:Policy>\n" +
                        "                                        <sp:WssX509V3Token11/>\n" +
                        "                                    </wsp:Policy>\n" +
                        "                                </sp:X509Token>\n" +
                        "                            </wsp:Policy>\n" +
                        "                        </sp:InitiatorToken>\n" +
                        "                        <sp:RecipientToken>\n" +
                        "                            <wsp:Policy>\n" +
                        "                              <sp:X509Token IncludeToken=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702/IncludeToken/AlwaysToRecipient\">\n" +
                        "                                  <sp:IssuerName>CN=receiver,OU=swssf,C=CH</sp:IssuerName>\n" +
                        "                                  <wsp:Policy>\n" +
                        "                                      <sp:WssX509V3Token11/>\n" +
                        "                                  </wsp:Policy>\n" +
                        "                              </sp:X509Token>\n" +
                        "                            </wsp:Policy>\n" +
                        "                         </sp:RecipientToken>\n" +
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
                        "                        <sp:OnlySignEntireHeadersAndBody/>\n" +
                        "                    </wsp:Policy>\n" +
                        "                </sp:AsymmetricBinding>\n" +
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

        outSecurityProperties.addSignaturePart(new SecurePart(WSSConstants.TAG_wsu_Timestamp, SecurePart.Modifier.Element));
        outSecurityProperties.addSignaturePart(new SecurePart(WSSConstants.TAG_soap11_Body, SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_wsu_Created, SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_wsu_Expires, SecurePart.Modifier.Content));
        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_soap11_Body, SecurePart.Modifier.Content));
        WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.TIMESTAMP, WSSConstants.SIGNATURE, WSSConstants.ENCRYPT};
        outSecurityProperties.setOutAction(actions);

        InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
        ByteArrayOutputStream baos = doOutboundSecurity(outSecurityProperties, sourceDocument);

        WSSSecurityProperties inSecurityProperties = new WSSSecurityProperties();
        inSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
        inSecurityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
        inSecurityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());

        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);
        inSecurityProperties.addInputProcessor(new PolicyInputProcessor(policyEnforcer, inSecurityProperties));

        try {
            Document document = doInboundSecurity(inSecurityProperties, new ByteArrayInputStream(baos.toByteArray()), policyEnforcer);

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
                    "\torg.swssf.policy.PolicyViolationException: \n" +
                    "Element /{http://schemas.xmlsoap.org/soap/envelope/}Envelope/{http://schemas.xmlsoap.org/soap/envelope/}Header/{http://schemas.xmlsoap.org/wsdl/}definitions must be signed");
        }
    }

    /*@Test
    public void testLayoutLaxTimestampFirstNegative() throws Exception {

        String policyString =
                "<wsp:ExactlyOne xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\" " +
                        "xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\">\n" +
                        "            <wsp:All>\n" +
                        "                <sp:AsymmetricBinding>\n" +
                        "                    <wsp:Policy>\n" +
                        "                        <sp:InitiatorToken>\n" +
                        "                            <wsp:Policy>\n" +
                        "                                <sp:X509Token IncludeToken=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702/IncludeToken/AlwaysToRecipient\">\n" +
                        "                                    <sp:IssuerName>CN=transmitter,OU=swssf,C=CH</sp:IssuerName>\n" +
                        "                                    <wsp:Policy>\n" +
                        "                                        <sp:WssX509V3Token11/>\n" +
                        "                                    </wsp:Policy>\n" +
                        "                                </sp:X509Token>\n" +
                        "                            </wsp:Policy>\n" +
                        "                        </sp:InitiatorToken>\n" +
                        "                        <sp:RecipientToken>\n" +
                        "                            <wsp:Policy>\n" +
                        "                              <sp:X509Token IncludeToken=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702/IncludeToken/AlwaysToRecipient\">\n" +
                        "                                  <sp:IssuerName>CN=receiver,OU=swssf,C=CH</sp:IssuerName>\n" +
                        "                                  <wsp:Policy>\n" +
                        "                                      <sp:WssX509V3Token11/>\n" +
                        "                                  </wsp:Policy>\n" +
                        "                              </sp:X509Token>\n" +
                        "                            </wsp:Policy>\n" +
                        "                         </sp:RecipientToken>\n" +
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
                        "                </sp:AsymmetricBinding>\n" +
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

        outSecurityProperties.addSignaturePart(new SecurePart(WSSConstants.TAG_wsu_Timestamp, SecurePart.Modifier.Element));
        outSecurityProperties.addSignaturePart(new SecurePart(WSSConstants.TAG_soap11_Body, SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_wsu_Created, SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_wsu_Expires, SecurePart.Modifier.Content));
        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_soap11_Body, SecurePart.Modifier.Content));
        WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.TIMESTAMP, WSSConstants.SIGNATURE, WSSConstants.ENCRYPT};
        outSecurityProperties.setOutAction(actions);

        InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
        ByteArrayOutputStream baos = doOutboundSecurity(outSecurityProperties, sourceDocument);

        WSSSecurityProperties inSecurityProperties = new WSSSecurityProperties();
        inSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
        inSecurityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
        inSecurityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());

        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);
        inSecurityProperties.addInputProcessor(new PolicyInputProcessor(policyEnforcer, inSecurityProperties));

        try {
            Document document = doInboundSecurity(inSecurityProperties, new ByteArrayInputStream(baos.toByteArray()), policyEnforcer);

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
                    "\torg.swssf.policy.PolicyViolationException: \n" +
                    "Policy enforces LaxTsFirst but X509Token occured first");
        }
    }*/

    @Test
    public void testTokenScenario() throws Exception {

        String policyString =
                "<wsp:ExactlyOne xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\" " +
                        "xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\">\n" +
                        "            <wsp:All>\n" +
                        "                <sp:AsymmetricBinding>\n" +
                        "                    <wsp:Policy>\n" +
                        "                        <sp:InitiatorToken>\n" +
                        "                            <wsp:Policy>\n" +
                        "                               <sp:SamlToken IncludeToken=\" http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702/IncludeToken/Always\">\n" +
                        "                                  <sp:IssuerName>www.example.com</sp:IssuerName>\n" +
                        "                                    <wsp:Policy xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">\n" +
                        "                                        <sp:WssSamlV20Token11/>\n" +
                        "                                    </wsp:Policy>\n" +
                        "                                </sp:SamlToken>\n" +
                        "                            </wsp:Policy>\n" +
                        "                        </sp:InitiatorToken>\n" +
                        "                        <sp:RecipientToken>\n" +
                        "                            <wsp:Policy>\n" +
                        "                              <sp:X509Token IncludeToken=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702/IncludeToken/AlwaysToRecipient\">\n" +
                        "                                  <sp:IssuerName>CN=receiver,OU=swssf,C=CH</sp:IssuerName>\n" +
                        "                                  <wsp:Policy>\n" +
                        "                                      <sp:RequireDerivedKeys/>\n" +
                        "                                      <sp:WssX509V3Token11/>\n" +
                        "                                  </wsp:Policy>\n" +
                        "                              </sp:X509Token>\n" +
                        "                            </wsp:Policy>\n" +
                        "                         </sp:RecipientToken>\n" +
                        "                        <sp:AlgorithmSuite>\n" +
                        "                            <wsp:Policy>\n" +
                        "                                <sp:Basic256/>\n" +
                        "                            </wsp:Policy>\n" +
                        "                        </sp:AlgorithmSuite>\n" +
                        "                        <sp:IncludeTimestamp/>\n" +
                        "                    </wsp:Policy>\n" +
                        "                </sp:AsymmetricBinding>\n" +
                        "                <sp:SignedSupportingTokens>\n" +
                        "                   <wsp:Policy>\n" +
                        "                     <sp:UsernameToken IncludeToken=\" http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702/IncludeToken/AlwaysToRecipient\">\n" +
                        "                       <wsp:Policy>\n" +
                        "                       </wsp:Policy>\n" +
                        "                     </sp:UsernameToken>\n" +
                        "                   </wsp:Policy>\n" +
                        "                </sp:SignedSupportingTokens>\n" +
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
                        "            </wsp:All>\n" +
                        "        </wsp:ExactlyOne>";

        WSSSecurityProperties outSecurityProperties = new WSSSecurityProperties();
        WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.TIMESTAMP, WSSConstants.USERNAMETOKEN, WSSConstants.SAML_TOKEN_SIGNED, WSSConstants.ENCRYPT_WITH_DERIVED_KEY};
        outSecurityProperties.setOutAction(actions);
        CallbackHandlerImpl callbackHandler = new CallbackHandlerImpl();
        callbackHandler.setSamlVersion(SAMLVersion.VERSION_20);
        callbackHandler.setStatement(CallbackHandlerImpl.Statement.AUTHN);
        callbackHandler.setConfirmationMethod(SAML2Constants.CONF_HOLDER_KEY);
        callbackHandler.setIssuer("www.example.com");
        byte[] secret = new byte[128 / 8];
        WSSConstants.secureRandom.nextBytes(secret);
        callbackHandler.setSecret(secret);
        KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(this.getClass().getClassLoader().getResourceAsStream("transmitter.jks"), "default".toCharArray());
        Merlin crypto = new Merlin();
        crypto.setKeyStore(keyStore);
        CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
        cryptoType.setAlias("transmitter");
        callbackHandler.setCerts(crypto.getX509Certificates(cryptoType));
        outSecurityProperties.setCallbackHandler(callbackHandler);
        outSecurityProperties.setTokenUser("tester");
        outSecurityProperties.setSignatureKeyIdentifierType(WSSConstants.WSSKeyIdentifierType.EMBEDDED_KEYIDENTIFIER_REF);
        outSecurityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
        outSecurityProperties.setSignatureUser("transmitter");
        outSecurityProperties.addSignaturePart(new SecurePart(WSSConstants.TAG_soap11_Body, SecurePart.Modifier.Element));
        outSecurityProperties.addSignaturePart(new SecurePart(WSSConstants.TAG_wsse_UsernameToken, SecurePart.Modifier.Element));
        outSecurityProperties.addSignaturePart(new SecurePart(WSSConstants.TAG_wsu_Timestamp, SecurePart.Modifier.Element));
        outSecurityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
        outSecurityProperties.setEncryptionUser("receiver");
        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_soap11_Body, SecurePart.Modifier.Content));
        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_wsu_Created, SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_wsu_Expires, SecurePart.Modifier.Content));

        InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
        ByteArrayOutputStream baos = doOutboundSecurity(outSecurityProperties, sourceDocument);

        WSSSecurityProperties inSecurityProperties = new WSSSecurityProperties();
        inSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
        inSecurityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
        inSecurityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());

        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);
        inSecurityProperties.addInputProcessor(new PolicyInputProcessor(policyEnforcer, inSecurityProperties));
        Document document = doInboundSecurity(inSecurityProperties, new ByteArrayInputStream(baos.toByteArray()), policyEnforcer);

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
    public void testTokenScenarioLateEncryption() throws Exception {

        String policyString =
                "<wsp:ExactlyOne xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\" " +
                        "xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\">\n" +
                        "            <wsp:All>\n" +
                        "                <sp:AsymmetricBinding>\n" +
                        "                    <wsp:Policy>\n" +
                        "                        <sp:InitiatorToken>\n" +
                        "                            <wsp:Policy>\n" +
                        "                               <sp:SamlToken IncludeToken=\" http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702/IncludeToken/Always\">\n" +
                        "                                  <sp:IssuerName>www.example.com</sp:IssuerName>\n" +
                        "                                    <wsp:Policy xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">\n" +
                        "                                        <sp:WssSamlV20Token11/>\n" +
                        "                                    </wsp:Policy>\n" +
                        "                                </sp:SamlToken>\n" +
                        "                            </wsp:Policy>\n" +
                        "                        </sp:InitiatorToken>\n" +
                        "                        <sp:RecipientToken>\n" +
                        "                            <wsp:Policy>\n" +
                        "                              <sp:X509Token IncludeToken=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702/IncludeToken/AlwaysToRecipient\">\n" +
                        "                                  <sp:IssuerName>CN=receiver,OU=swssf,C=CH</sp:IssuerName>\n" +
                        "                                  <wsp:Policy>\n" +
                        "                                      <sp:RequireDerivedKeys/>\n" +
                        "                                      <sp:WssX509V3Token11/>\n" +
                        "                                  </wsp:Policy>\n" +
                        "                              </sp:X509Token>\n" +
                        "                            </wsp:Policy>\n" +
                        "                         </sp:RecipientToken>\n" +
                        "                        <sp:AlgorithmSuite>\n" +
                        "                            <wsp:Policy>\n" +
                        "                                <sp:Basic256/>\n" +
                        "                            </wsp:Policy>\n" +
                        "                        </sp:AlgorithmSuite>\n" +
                        "                        <sp:IncludeTimestamp/>\n" +
                        "                    </wsp:Policy>\n" +
                        "                </sp:AsymmetricBinding>\n" +
                        "                <sp:SignedSupportingTokens>\n" +
                        "                   <wsp:Policy>\n" +
                        "                     <sp:UsernameToken IncludeToken=\" http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702/IncludeToken/AlwaysToRecipient\">\n" +
                        "                       <wsp:Policy>\n" +
                        "                       </wsp:Policy>\n" +
                        "                     </sp:UsernameToken>\n" +
                        "                   </wsp:Policy>\n" +
                        "                </sp:SignedSupportingTokens>\n" +
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
                        "                <sp:EncryptedElements>\n" +
                        "                    <sp:XPath xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\" " +
                        "                       xmlns:wsdl=\"http://schemas.xmlsoap.org/wsdl/\" " +
                        "                       xmlns:xsd=\"http://www.w3.org/1999/XMLSchema\">" +
                        "                       /soap:Envelope/soap:Body/wsdl:definitions/wsdl:types/xsd:schema/xsd:simpleType" +
                        "                    </sp:XPath>\n" +
                        "                </sp:EncryptedElements>\n" +
                        "            </wsp:All>\n" +
                        "        </wsp:ExactlyOne>";

        WSSSecurityProperties outSecurityProperties = new WSSSecurityProperties();
        WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.TIMESTAMP, WSSConstants.USERNAMETOKEN, WSSConstants.SAML_TOKEN_SIGNED, WSSConstants.ENCRYPT_WITH_DERIVED_KEY};
        outSecurityProperties.setOutAction(actions);
        CallbackHandlerImpl callbackHandler = new CallbackHandlerImpl();
        callbackHandler.setSamlVersion(SAMLVersion.VERSION_20);
        callbackHandler.setStatement(CallbackHandlerImpl.Statement.AUTHN);
        callbackHandler.setConfirmationMethod(SAML2Constants.CONF_HOLDER_KEY);
        callbackHandler.setIssuer("www.example.com");
        byte[] secret = new byte[128 / 8];
        WSSConstants.secureRandom.nextBytes(secret);
        callbackHandler.setSecret(secret);
        KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(this.getClass().getClassLoader().getResourceAsStream("transmitter.jks"), "default".toCharArray());
        Merlin crypto = new Merlin();
        crypto.setKeyStore(keyStore);
        CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
        cryptoType.setAlias("transmitter");
        callbackHandler.setCerts(crypto.getX509Certificates(cryptoType));
        outSecurityProperties.setCallbackHandler(callbackHandler);
        outSecurityProperties.setTokenUser("tester");
        outSecurityProperties.setSignatureKeyIdentifierType(WSSConstants.WSSKeyIdentifierType.EMBEDDED_KEYIDENTIFIER_REF);
        outSecurityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
        outSecurityProperties.setSignatureUser("transmitter");
        outSecurityProperties.addSignaturePart(new SecurePart(WSSConstants.TAG_soap11_Body, SecurePart.Modifier.Element));
        outSecurityProperties.addSignaturePart(new SecurePart(WSSConstants.TAG_wsse_UsernameToken, SecurePart.Modifier.Element));
        outSecurityProperties.addSignaturePart(new SecurePart(WSSConstants.TAG_wsu_Timestamp, SecurePart.Modifier.Element));
        outSecurityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
        outSecurityProperties.setEncryptionUser("receiver");
        outSecurityProperties.addEncryptionPart(new SecurePart(new QName("http://www.w3.org/1999/XMLSchema", "simpleType"), SecurePart.Modifier.Element));

        InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
        ByteArrayOutputStream baos = doOutboundSecurity(outSecurityProperties, sourceDocument);

        WSSSecurityProperties inSecurityProperties = new WSSSecurityProperties();
        inSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
        inSecurityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
        inSecurityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());

        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);
        inSecurityProperties.addInputProcessor(new PolicyInputProcessor(policyEnforcer, inSecurityProperties));
        Document document = doInboundSecurity(inSecurityProperties, new ByteArrayInputStream(baos.toByteArray()), policyEnforcer);

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
}
