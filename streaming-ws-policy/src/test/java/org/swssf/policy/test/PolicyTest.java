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

import org.swssf.policy.PolicyEnforcer;
import org.swssf.policy.PolicyEnforcerFactory;
import org.swssf.policy.PolicyInputProcessor;
import org.swssf.policy.PolicyViolationException;
import org.swssf.wss.ext.WSSConstants;
import org.swssf.wss.ext.WSSSecurityProperties;
import org.swssf.wss.impl.securityToken.HttpsSecurityToken;
import org.swssf.wss.securityEvent.HttpsTokenSecurityEvent;
import org.swssf.wss.securityEvent.SecurityEvent;
import org.swssf.wss.test.AbstractTestBase;
import org.swssf.wss.test.CallbackHandlerImpl;
import org.swssf.xmlsec.ext.SecurePart;
import org.testng.Assert;
import org.testng.annotations.Test;
import org.w3c.dom.Document;

import javax.xml.stream.XMLStreamException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.*;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class PolicyTest extends AbstractTestBase {

    @Test
    public void testAsymmetricBindingIncludeTimestampPolicy() throws Exception {

        WSSSecurityProperties outSecurityProperties = new WSSSecurityProperties();
        outSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
        outSecurityProperties.setEncryptionUser("receiver");
        outSecurityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
        outSecurityProperties.setSignatureUser("transmitter");
        outSecurityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());

        outSecurityProperties.addSignaturePart(new SecurePart(WSSConstants.TAG_wsu_Timestamp.getLocalPart(), WSSConstants.TAG_wsu_Timestamp.getNamespaceURI(), SecurePart.Modifier.Element));
        outSecurityProperties.addSignaturePart(new SecurePart(WSSConstants.TAG_soap_Body_LocalName, WSSConstants.NS_SOAP11, SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_wsu_Created.getLocalPart(), WSSConstants.TAG_wsu_Created.getNamespaceURI(), SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_wsu_Expires.getLocalPart(), WSSConstants.TAG_wsu_Expires.getNamespaceURI(), SecurePart.Modifier.Content));
        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_soap_Body_LocalName, WSSConstants.NS_SOAP11, SecurePart.Modifier.Content));
        WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.TIMESTAMP, WSSConstants.SIGNATURE, WSSConstants.ENCRYPT};
        outSecurityProperties.setOutAction(actions);

        InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
        ByteArrayOutputStream baos = doOutboundSecurity(outSecurityProperties, sourceDocument);

        WSSSecurityProperties inSecurityProperties = new WSSSecurityProperties();
        inSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
        inSecurityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
        inSecurityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());

        PolicyEnforcerFactory policyEnforcerFactory = PolicyEnforcerFactory.newInstance(this.getClass().getClassLoader().getResource("testdata/wsdl/testAsymmetricBindingIncludeTimestampPolicy.wsdl"));
        PolicyEnforcer policyEnforcer = policyEnforcerFactory.newPolicyEnforcer(null);
        inSecurityProperties.addInputProcessor(new PolicyInputProcessor(policyEnforcer, null));

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
    public void testAsymmetricBindingIncludeTimestampPolicyNegativeTest() throws Exception {

        WSSSecurityProperties outSecurityProperties = new WSSSecurityProperties();
        outSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
        outSecurityProperties.setEncryptionUser("receiver");
        outSecurityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
        outSecurityProperties.setSignatureUser("transmitter");
        outSecurityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());

        outSecurityProperties.addSignaturePart(new SecurePart(WSSConstants.TAG_wsu_Timestamp.getLocalPart(), WSSConstants.TAG_wsu_Timestamp.getNamespaceURI(), SecurePart.Modifier.Element));
        outSecurityProperties.addSignaturePart(new SecurePart(WSSConstants.TAG_soap_Body_LocalName, WSSConstants.NS_SOAP11, SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_wsu_Created.getLocalPart(), WSSConstants.TAG_wsu_Created.getNamespaceURI(), SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_wsu_Expires.getLocalPart(), WSSConstants.TAG_wsu_Expires.getNamespaceURI(), SecurePart.Modifier.Content));
        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_soap_Body_LocalName, WSSConstants.NS_SOAP11, SecurePart.Modifier.Content));
        WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.TIMESTAMP, WSSConstants.SIGNATURE, WSSConstants.ENCRYPT};
        outSecurityProperties.setOutAction(actions);

        InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
        ByteArrayOutputStream baos = doOutboundSecurity(outSecurityProperties, sourceDocument);

        WSSSecurityProperties inSecurityProperties = new WSSSecurityProperties();
        inSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
        inSecurityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
        inSecurityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());

        PolicyEnforcerFactory policyEnforcerFactory = PolicyEnforcerFactory.newInstance(this.getClass().getClassLoader().getResource("testdata/wsdl/testAsymmetricBindingIncludeTimestampPolicyNegativeTest.wsdl"));
        PolicyEnforcer policyEnforcer = policyEnforcerFactory.newPolicyEnforcer(null);
        inSecurityProperties.addInputProcessor(new PolicyInputProcessor(policyEnforcer, null));

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
        } catch (XMLStreamException e) {
            Assert.assertTrue(e.getCause() instanceof PolicyViolationException);
            Assert.assertEquals(e.getCause().getMessage(), "No policy alternative could be satisfied");
        }
    }

    @Test
    public void testAsymmetricBindingIncludeTimestampAndSignedUsernameSupportingTokenPolicy() throws Exception {

        WSSSecurityProperties outSecurityProperties = new WSSSecurityProperties();
        outSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
        outSecurityProperties.setEncryptionUser("receiver");
        outSecurityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
        outSecurityProperties.setSignatureUser("transmitter");
        outSecurityProperties.setTokenUser("transmitter");
        outSecurityProperties.setUsernameTokenPasswordType(WSSConstants.UsernameTokenPasswordType.PASSWORD_NONE);
        outSecurityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());

        outSecurityProperties.addSignaturePart(new SecurePart(WSSConstants.TAG_wsu_Timestamp.getLocalPart(), WSSConstants.TAG_wsu_Timestamp.getNamespaceURI(), SecurePart.Modifier.Element));
        outSecurityProperties.addSignaturePart(new SecurePart(WSSConstants.TAG_soap_Body_LocalName, WSSConstants.NS_SOAP11, SecurePart.Modifier.Element));
        outSecurityProperties.addSignaturePart(new SecurePart(WSSConstants.TAG_wsse_UsernameToken.getLocalPart(), WSSConstants.TAG_wsse_UsernameToken.getNamespaceURI(), SecurePart.Modifier.Element));
        //outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_wsu_Timestamp.getLocalPart(), WSSConstants.TAG_wsu_Timestamp.getNamespaceURI(), SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_wsu_Created.getLocalPart(), WSSConstants.TAG_wsu_Created.getNamespaceURI(), SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_wsu_Expires.getLocalPart(), WSSConstants.TAG_wsu_Expires.getNamespaceURI(), SecurePart.Modifier.Content));
        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_soap_Body_LocalName, WSSConstants.NS_SOAP11, SecurePart.Modifier.Content));
        WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.USERNAMETOKEN, WSSConstants.TIMESTAMP, WSSConstants.SIGNATURE, WSSConstants.ENCRYPT};
        outSecurityProperties.setOutAction(actions);

        InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
        ByteArrayOutputStream baos = doOutboundSecurity(outSecurityProperties, sourceDocument);

        WSSSecurityProperties inSecurityProperties = new WSSSecurityProperties();
        inSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
        inSecurityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
        inSecurityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());

        PolicyEnforcerFactory policyEnforcerFactory = PolicyEnforcerFactory.newInstance(this.getClass().getClassLoader().getResource("testdata/wsdl/testAsymmetricBindingIncludeTimestampAndSignedUsernameSupportingTokenPolicy.wsdl"));
        PolicyEnforcer policyEnforcer = policyEnforcerFactory.newPolicyEnforcer(null);
        inSecurityProperties.addInputProcessor(new PolicyInputProcessor(policyEnforcer, null));

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
    public void testAsymmetricBindingIncludeTimestampAndSignedUsernameSupportingTokenPolicyNegativeTest() throws Exception {

        WSSSecurityProperties outSecurityProperties = new WSSSecurityProperties();
        outSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
        outSecurityProperties.setEncryptionUser("receiver");
        outSecurityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
        outSecurityProperties.setSignatureUser("transmitter");
        outSecurityProperties.setTokenUser("transmitter");
        outSecurityProperties.setUsernameTokenPasswordType(WSSConstants.UsernameTokenPasswordType.PASSWORD_NONE);
        outSecurityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());

        outSecurityProperties.addSignaturePart(new SecurePart(WSSConstants.TAG_wsu_Timestamp.getLocalPart(), WSSConstants.TAG_wsu_Timestamp.getNamespaceURI(), SecurePart.Modifier.Element));
        outSecurityProperties.addSignaturePart(new SecurePart(WSSConstants.TAG_soap_Body_LocalName, WSSConstants.NS_SOAP11, SecurePart.Modifier.Element));
        //outSecurityProperties.addSignaturePart(new SecurePart(WSSConstants.TAG_wsse_UsernameToken.getLocalPart(), WSSConstants.TAG_wsse_UsernameToken.getNamespaceURI(), SecurePart.Modifier.Element));
        //outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_wsu_Timestamp.getLocalPart(), WSSConstants.TAG_wsu_Timestamp.getNamespaceURI(), SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_wsu_Created.getLocalPart(), WSSConstants.TAG_wsu_Created.getNamespaceURI(), SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_wsu_Expires.getLocalPart(), WSSConstants.TAG_wsu_Expires.getNamespaceURI(), SecurePart.Modifier.Content));
        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_soap_Body_LocalName, WSSConstants.NS_SOAP11, SecurePart.Modifier.Content));
        WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.USERNAMETOKEN, WSSConstants.TIMESTAMP, WSSConstants.SIGNATURE, WSSConstants.ENCRYPT};
        outSecurityProperties.setOutAction(actions);

        InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
        ByteArrayOutputStream baos = doOutboundSecurity(outSecurityProperties, sourceDocument);

        WSSSecurityProperties inSecurityProperties = new WSSSecurityProperties();
        inSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
        inSecurityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
        inSecurityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());

        PolicyEnforcerFactory policyEnforcerFactory = PolicyEnforcerFactory.newInstance(this.getClass().getClassLoader().getResource("testdata/wsdl/testAsymmetricBindingIncludeTimestampAndSignedUsernameSupportingTokenPolicy.wsdl"));
        PolicyEnforcer policyEnforcer = policyEnforcerFactory.newPolicyEnforcer(null);
        inSecurityProperties.addInputProcessor(new PolicyInputProcessor(policyEnforcer, null));

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
        } catch (XMLStreamException e) {
            Assert.assertTrue(e.getCause() instanceof PolicyViolationException);
            Assert.assertEquals(e.getCause().getMessage(), "No policy alternative could be satisfied");
        }
    }

    @Test
    public void testAsymmetricBindingIncludeTimestampAndProtectionOrderSignBeforeEncryptAndSignedUsernameSupportingTokenPolicyNegativeTest() throws Exception {

        WSSSecurityProperties outSecurityProperties = new WSSSecurityProperties();
        outSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
        outSecurityProperties.setEncryptionUser("receiver");
        outSecurityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
        outSecurityProperties.setSignatureUser("transmitter");
        outSecurityProperties.setTokenUser("transmitter");
        outSecurityProperties.setUsernameTokenPasswordType(WSSConstants.UsernameTokenPasswordType.PASSWORD_NONE);
        outSecurityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());

        outSecurityProperties.addSignaturePart(new SecurePart(WSSConstants.TAG_wsu_Timestamp.getLocalPart(), WSSConstants.TAG_wsu_Timestamp.getNamespaceURI(), SecurePart.Modifier.Element));
        outSecurityProperties.addSignaturePart(new SecurePart(WSSConstants.TAG_soap_Body_LocalName, WSSConstants.NS_SOAP11, SecurePart.Modifier.Element));
        outSecurityProperties.addSignaturePart(new SecurePart(WSSConstants.TAG_wsse_UsernameToken.getLocalPart(), WSSConstants.TAG_wsse_UsernameToken.getNamespaceURI(), SecurePart.Modifier.Element));
        //outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_wsu_Timestamp.getLocalPart(), WSSConstants.TAG_wsu_Timestamp.getNamespaceURI(), SecurePart.Modifier.Element));
        //outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_wsu_Created.getLocalPart(), WSSConstants.TAG_wsu_Created.getNamespaceURI(), SecurePart.Modifier.Element));
        //outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_wsu_Expires.getLocalPart(), WSSConstants.TAG_wsu_Expires.getNamespaceURI(), SecurePart.Modifier.Content));
        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_soap_Body_LocalName, WSSConstants.NS_SOAP11, SecurePart.Modifier.Content));
        WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.USERNAMETOKEN, WSSConstants.TIMESTAMP, WSSConstants.ENCRYPT, WSSConstants.SIGNATURE};
        outSecurityProperties.setOutAction(actions);

        InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
        ByteArrayOutputStream baos = doOutboundSecurity(outSecurityProperties, sourceDocument);

        WSSSecurityProperties inSecurityProperties = new WSSSecurityProperties();
        inSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
        inSecurityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
        inSecurityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());

        PolicyEnforcerFactory policyEnforcerFactory = PolicyEnforcerFactory.newInstance(this.getClass().getClassLoader().getResource("testdata/wsdl/testAsymmetricBindingIncludeTimestampAndProtectionOrderSignBeforeEncryptAndSignedUsernameSupportingTokenPolicyNegativeTest.wsdl"));
        PolicyEnforcer policyEnforcer = policyEnforcerFactory.newPolicyEnforcer(null);
        inSecurityProperties.addInputProcessor(new PolicyInputProcessor(policyEnforcer, null));

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
    public void testTransportBindingBasicAuthenticationIncludeTimestampAndSignedUsernameSupportingTokenPolicy() throws Exception {

        WSSSecurityProperties outSecurityProperties = new WSSSecurityProperties();
        outSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
        outSecurityProperties.setEncryptionUser("receiver");
        outSecurityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
        outSecurityProperties.setSignatureUser("transmitter");
        outSecurityProperties.setTokenUser("transmitter");
        outSecurityProperties.setUsernameTokenPasswordType(WSSConstants.UsernameTokenPasswordType.PASSWORD_NONE);
        outSecurityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());

        outSecurityProperties.addSignaturePart(new SecurePart(WSSConstants.TAG_wsu_Timestamp.getLocalPart(), WSSConstants.TAG_wsu_Timestamp.getNamespaceURI(), SecurePart.Modifier.Element));
        outSecurityProperties.addSignaturePart(new SecurePart(WSSConstants.TAG_soap_Body_LocalName, WSSConstants.NS_SOAP11, SecurePart.Modifier.Element));
        //outSecurityProperties.addSignaturePart(new SecurePart(WSSConstants.TAG_wsse_UsernameToken.getLocalPart(), WSSConstants.TAG_wsse_UsernameToken.getNamespaceURI(), SecurePart.Modifier.Element));
        //outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_wsu_Timestamp.getLocalPart(), WSSConstants.TAG_wsu_Timestamp.getNamespaceURI(), SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_wsu_Created.getLocalPart(), WSSConstants.TAG_wsu_Created.getNamespaceURI(), SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_wsu_Expires.getLocalPart(), WSSConstants.TAG_wsu_Expires.getNamespaceURI(), SecurePart.Modifier.Content));
        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_soap_Body_LocalName, WSSConstants.NS_SOAP11, SecurePart.Modifier.Content));
        WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.USERNAMETOKEN, WSSConstants.TIMESTAMP, WSSConstants.SIGNATURE, WSSConstants.ENCRYPT};
        outSecurityProperties.setOutAction(actions);

        InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
        ByteArrayOutputStream baos = doOutboundSecurity(outSecurityProperties, sourceDocument);

        WSSSecurityProperties inSecurityProperties = new WSSSecurityProperties();
        inSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
        inSecurityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
        inSecurityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());

        PolicyEnforcerFactory policyEnforcerFactory = PolicyEnforcerFactory.newInstance(this.getClass().getClassLoader().getResource("testdata/wsdl/testTransportBindingBasicAuthenticationIncludeTimestampAndSignedUsernameSupportingTokenPolicy.wsdl"));
        PolicyEnforcer policyEnforcer = policyEnforcerFactory.newPolicyEnforcer(null);
        inSecurityProperties.addInputProcessor(new PolicyInputProcessor(policyEnforcer, null));

        HttpsTokenSecurityEvent httpsTokenSecurityEvent = new HttpsTokenSecurityEvent(SecurityEvent.Event.HttpsToken);
        httpsTokenSecurityEvent.setIssuerName("transmitter");
        httpsTokenSecurityEvent.setAuthenticationType(HttpsTokenSecurityEvent.AuthenticationType.HttpBasicAuthentication);
        httpsTokenSecurityEvent.setSecurityToken(new HttpsSecurityToken(true, "transmitter"));
        policyEnforcer.registerSecurityEvent(httpsTokenSecurityEvent);

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
    public void testTransportBindingBasicAuthenticationIncludeTimestampAndSignedUsernameSupportingTokenPolicyNegativeTest() throws Exception {

        WSSSecurityProperties outSecurityProperties = new WSSSecurityProperties();
        outSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
        outSecurityProperties.setEncryptionUser("receiver");
        outSecurityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
        outSecurityProperties.setSignatureUser("transmitter");
        outSecurityProperties.setTokenUser("transmitter");
        outSecurityProperties.setUsernameTokenPasswordType(WSSConstants.UsernameTokenPasswordType.PASSWORD_NONE);
        outSecurityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());

        outSecurityProperties.addSignaturePart(new SecurePart(WSSConstants.TAG_wsu_Timestamp.getLocalPart(), WSSConstants.TAG_wsu_Timestamp.getNamespaceURI(), SecurePart.Modifier.Element));
        outSecurityProperties.addSignaturePart(new SecurePart(WSSConstants.TAG_soap_Body_LocalName, WSSConstants.NS_SOAP11, SecurePart.Modifier.Element));
        //outSecurityProperties.addSignaturePart(new SecurePart(WSSConstants.TAG_wsse_UsernameToken.getLocalPart(), WSSConstants.TAG_wsse_UsernameToken.getNamespaceURI(), SecurePart.Modifier.Element));
        //outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_wsu_Timestamp.getLocalPart(), WSSConstants.TAG_wsu_Timestamp.getNamespaceURI(), SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_wsu_Created.getLocalPart(), WSSConstants.TAG_wsu_Created.getNamespaceURI(), SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_wsu_Expires.getLocalPart(), WSSConstants.TAG_wsu_Expires.getNamespaceURI(), SecurePart.Modifier.Content));
        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_soap_Body_LocalName, WSSConstants.NS_SOAP11, SecurePart.Modifier.Content));
        WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.USERNAMETOKEN, WSSConstants.TIMESTAMP, WSSConstants.SIGNATURE, WSSConstants.ENCRYPT};
        outSecurityProperties.setOutAction(actions);

        InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
        ByteArrayOutputStream baos = doOutboundSecurity(outSecurityProperties, sourceDocument);

        WSSSecurityProperties inSecurityProperties = new WSSSecurityProperties();
        inSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
        inSecurityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
        inSecurityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());

        PolicyEnforcerFactory policyEnforcerFactory = PolicyEnforcerFactory.newInstance(this.getClass().getClassLoader().getResource("testdata/wsdl/testTransportBindingBasicAuthenticationIncludeTimestampAndSignedUsernameSupportingTokenPolicy.wsdl"));
        PolicyEnforcer policyEnforcer = policyEnforcerFactory.newPolicyEnforcer(null);
        inSecurityProperties.addInputProcessor(new PolicyInputProcessor(policyEnforcer, null));

/*
        HttpsTokenSecurityEvent httpsTokenSecurityEvent = new HttpsTokenSecurityEvent(SecurityEvent.Event.TransportToken);
        httpsTokenSecurityEvent.setIssuerName("CN=transmitter,OU=swssf,C=CH");
        httpsTokenSecurityEvent.setAuthenticationType(HttpsTokenSecurityEvent.AuthenticationType.HttpBasicAuthentication);
        httpsTokenSecurityEvent.setSecurityToken(new HttpsSecurityToken((X509Certificate)outSecurityProperties.getSignatureKeyStore().getCertificate("transmitter")));
        policyEnforcer.registerSecurityEvent(httpsTokenSecurityEvent);
*/

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
        } catch (XMLStreamException e) {
            Assert.assertTrue(e.getCause() instanceof PolicyViolationException);
            Assert.assertEquals(e.getCause().getMessage(), "No policy alternative could be satisfied");
        }
    }

    @Test
    public void testTransportBindingHttpsClientAuthenticationIncludeTimestampAndSignedUsernameSupportingTokenPolicy() throws Exception {

        WSSSecurityProperties outSecurityProperties = new WSSSecurityProperties();
        outSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
        outSecurityProperties.setEncryptionUser("receiver");
        outSecurityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
        outSecurityProperties.setSignatureUser("transmitter");
        outSecurityProperties.setTokenUser("transmitter");
        outSecurityProperties.setUsernameTokenPasswordType(WSSConstants.UsernameTokenPasswordType.PASSWORD_NONE);
        outSecurityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());

        outSecurityProperties.addSignaturePart(new SecurePart(WSSConstants.TAG_wsu_Timestamp.getLocalPart(), WSSConstants.TAG_wsu_Timestamp.getNamespaceURI(), SecurePart.Modifier.Element));
        outSecurityProperties.addSignaturePart(new SecurePart(WSSConstants.TAG_soap_Body_LocalName, WSSConstants.NS_SOAP11, SecurePart.Modifier.Element));
        //outSecurityProperties.addSignaturePart(new SecurePart(WSSConstants.TAG_wsse_UsernameToken.getLocalPart(), WSSConstants.TAG_wsse_UsernameToken.getNamespaceURI(), SecurePart.Modifier.Element));
        //outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_wsu_Timestamp.getLocalPart(), WSSConstants.TAG_wsu_Timestamp.getNamespaceURI(), SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_wsu_Created.getLocalPart(), WSSConstants.TAG_wsu_Created.getNamespaceURI(), SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_wsu_Expires.getLocalPart(), WSSConstants.TAG_wsu_Expires.getNamespaceURI(), SecurePart.Modifier.Content));
        outSecurityProperties.addEncryptionPart(new SecurePart(WSSConstants.TAG_soap_Body_LocalName, WSSConstants.NS_SOAP11, SecurePart.Modifier.Content));
        WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.USERNAMETOKEN, WSSConstants.TIMESTAMP, WSSConstants.SIGNATURE, WSSConstants.ENCRYPT};
        outSecurityProperties.setOutAction(actions);

        InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
        ByteArrayOutputStream baos = doOutboundSecurity(outSecurityProperties, sourceDocument);

        WSSSecurityProperties inSecurityProperties = new WSSSecurityProperties();
        inSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
        inSecurityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
        inSecurityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());

        PolicyEnforcerFactory policyEnforcerFactory = PolicyEnforcerFactory.newInstance(this.getClass().getClassLoader().getResource("testdata/wsdl/testTransportBindingHttpsClientAuthenticationIncludeTimestampAndSignedUsernameSupportingTokenPolicy.wsdl"));
        PolicyEnforcer policyEnforcer = policyEnforcerFactory.newPolicyEnforcer(null);
        inSecurityProperties.addInputProcessor(new PolicyInputProcessor(policyEnforcer, null));

        HttpsTokenSecurityEvent httpsTokenSecurityEvent = new HttpsTokenSecurityEvent(SecurityEvent.Event.HttpsToken);
        httpsTokenSecurityEvent.setIssuerName("CN=transmitter,OU=swssf,C=CH");
        httpsTokenSecurityEvent.setAuthenticationType(HttpsTokenSecurityEvent.AuthenticationType.HttpsClientCertificateAuthentication);
        httpsTokenSecurityEvent.setSecurityToken(new HttpsSecurityToken(true, "CN=transmitter,OU=swssf,C=CH"));
        policyEnforcer.registerSecurityEvent(httpsTokenSecurityEvent);

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
