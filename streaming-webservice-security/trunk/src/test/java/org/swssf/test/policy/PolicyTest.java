/**
 * Copyright 2010, 2011 Marc Giger
 *
 * This file is part of the streaming-webservice-security-framework (swssf).
 *
 * The streaming-webservice-security-framework is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * The streaming-webservice-security-framework is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with the streaming-webservice-security-framework.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.swssf.test.policy;

import org.swssf.ext.Constants;
import org.swssf.ext.SecurePart;
import org.swssf.ext.SecurityProperties;
import org.swssf.impl.securityToken.HttpsSecurityToken;
import org.swssf.policy.PolicyEnforcer;
import org.swssf.policy.PolicyEnforcerFactory;
import org.swssf.policy.PolicyInputProcessor;
import org.swssf.policy.PolicyViolationException;
import org.swssf.securityEvent.HttpsTokenSecurityEvent;
import org.swssf.securityEvent.SecurityEvent;
import org.swssf.test.AbstractTestBase;
import org.swssf.test.CallbackHandlerImpl;
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

        SecurityProperties outSecurityProperties = new SecurityProperties();
        outSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
        outSecurityProperties.setEncryptionUser("receiver");
        outSecurityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
        outSecurityProperties.setSignatureUser("transmitter");
        outSecurityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());

        outSecurityProperties.addSignaturePart(new SecurePart(Constants.TAG_wsu_Timestamp.getLocalPart(), Constants.TAG_wsu_Timestamp.getNamespaceURI(), SecurePart.Modifier.Element));
        outSecurityProperties.addSignaturePart(new SecurePart(Constants.TAG_soap_Body_LocalName, Constants.NS_SOAP11, SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(Constants.TAG_wsu_Created.getLocalPart(), Constants.TAG_wsu_Created.getNamespaceURI(), SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(Constants.TAG_wsu_Expires.getLocalPart(), Constants.TAG_wsu_Expires.getNamespaceURI(), SecurePart.Modifier.Content));
        outSecurityProperties.addEncryptionPart(new SecurePart(Constants.TAG_soap_Body_LocalName, Constants.NS_SOAP11, SecurePart.Modifier.Content));
        Constants.Action[] actions = new Constants.Action[]{Constants.Action.TIMESTAMP, Constants.Action.SIGNATURE, Constants.Action.ENCRYPT};
        outSecurityProperties.setOutAction(actions);

        InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
        ByteArrayOutputStream baos = doOutboundSecurity(outSecurityProperties, sourceDocument);

        SecurityProperties inSecurityProperties = new SecurityProperties();
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

        SecurityProperties outSecurityProperties = new SecurityProperties();
        outSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
        outSecurityProperties.setEncryptionUser("receiver");
        outSecurityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
        outSecurityProperties.setSignatureUser("transmitter");
        outSecurityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());

        outSecurityProperties.addSignaturePart(new SecurePart(Constants.TAG_wsu_Timestamp.getLocalPart(), Constants.TAG_wsu_Timestamp.getNamespaceURI(), SecurePart.Modifier.Element));
        outSecurityProperties.addSignaturePart(new SecurePart(Constants.TAG_soap_Body_LocalName, Constants.NS_SOAP11, SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(Constants.TAG_wsu_Created.getLocalPart(), Constants.TAG_wsu_Created.getNamespaceURI(), SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(Constants.TAG_wsu_Expires.getLocalPart(), Constants.TAG_wsu_Expires.getNamespaceURI(), SecurePart.Modifier.Content));
        outSecurityProperties.addEncryptionPart(new SecurePart(Constants.TAG_soap_Body_LocalName, Constants.NS_SOAP11, SecurePart.Modifier.Content));
        Constants.Action[] actions = new Constants.Action[]{Constants.Action.TIMESTAMP, Constants.Action.SIGNATURE, Constants.Action.ENCRYPT};
        outSecurityProperties.setOutAction(actions);

        InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
        ByteArrayOutputStream baos = doOutboundSecurity(outSecurityProperties, sourceDocument);

        SecurityProperties inSecurityProperties = new SecurityProperties();
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

        SecurityProperties outSecurityProperties = new SecurityProperties();
        outSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
        outSecurityProperties.setEncryptionUser("receiver");
        outSecurityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
        outSecurityProperties.setSignatureUser("transmitter");
        outSecurityProperties.setTokenUser("transmitter");
        outSecurityProperties.setUsernameTokenPasswordType(Constants.UsernameTokenPasswordType.PASSWORD_NONE);
        outSecurityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());

        outSecurityProperties.addSignaturePart(new SecurePart(Constants.TAG_wsu_Timestamp.getLocalPart(), Constants.TAG_wsu_Timestamp.getNamespaceURI(), SecurePart.Modifier.Element));
        outSecurityProperties.addSignaturePart(new SecurePart(Constants.TAG_soap_Body_LocalName, Constants.NS_SOAP11, SecurePart.Modifier.Element));
        outSecurityProperties.addSignaturePart(new SecurePart(Constants.TAG_wsse_UsernameToken.getLocalPart(), Constants.TAG_wsse_UsernameToken.getNamespaceURI(), SecurePart.Modifier.Element));
        //outSecurityProperties.addEncryptionPart(new SecurePart(Constants.TAG_wsu_Timestamp.getLocalPart(), Constants.TAG_wsu_Timestamp.getNamespaceURI(), SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(Constants.TAG_wsu_Created.getLocalPart(), Constants.TAG_wsu_Created.getNamespaceURI(), SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(Constants.TAG_wsu_Expires.getLocalPart(), Constants.TAG_wsu_Expires.getNamespaceURI(), SecurePart.Modifier.Content));
        outSecurityProperties.addEncryptionPart(new SecurePart(Constants.TAG_soap_Body_LocalName, Constants.NS_SOAP11, SecurePart.Modifier.Content));
        Constants.Action[] actions = new Constants.Action[]{Constants.Action.USERNAMETOKEN, Constants.Action.TIMESTAMP, Constants.Action.SIGNATURE, Constants.Action.ENCRYPT};
        outSecurityProperties.setOutAction(actions);

        InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
        ByteArrayOutputStream baos = doOutboundSecurity(outSecurityProperties, sourceDocument);

        SecurityProperties inSecurityProperties = new SecurityProperties();
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

        SecurityProperties outSecurityProperties = new SecurityProperties();
        outSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
        outSecurityProperties.setEncryptionUser("receiver");
        outSecurityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
        outSecurityProperties.setSignatureUser("transmitter");
        outSecurityProperties.setTokenUser("transmitter");
        outSecurityProperties.setUsernameTokenPasswordType(Constants.UsernameTokenPasswordType.PASSWORD_NONE);
        outSecurityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());

        outSecurityProperties.addSignaturePart(new SecurePart(Constants.TAG_wsu_Timestamp.getLocalPart(), Constants.TAG_wsu_Timestamp.getNamespaceURI(), SecurePart.Modifier.Element));
        outSecurityProperties.addSignaturePart(new SecurePart(Constants.TAG_soap_Body_LocalName, Constants.NS_SOAP11, SecurePart.Modifier.Element));
        //outSecurityProperties.addSignaturePart(new SecurePart(Constants.TAG_wsse_UsernameToken.getLocalPart(), Constants.TAG_wsse_UsernameToken.getNamespaceURI(), SecurePart.Modifier.Element));
        //outSecurityProperties.addEncryptionPart(new SecurePart(Constants.TAG_wsu_Timestamp.getLocalPart(), Constants.TAG_wsu_Timestamp.getNamespaceURI(), SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(Constants.TAG_wsu_Created.getLocalPart(), Constants.TAG_wsu_Created.getNamespaceURI(), SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(Constants.TAG_wsu_Expires.getLocalPart(), Constants.TAG_wsu_Expires.getNamespaceURI(), SecurePart.Modifier.Content));
        outSecurityProperties.addEncryptionPart(new SecurePart(Constants.TAG_soap_Body_LocalName, Constants.NS_SOAP11, SecurePart.Modifier.Content));
        Constants.Action[] actions = new Constants.Action[]{Constants.Action.USERNAMETOKEN, Constants.Action.TIMESTAMP, Constants.Action.SIGNATURE, Constants.Action.ENCRYPT};
        outSecurityProperties.setOutAction(actions);

        InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
        ByteArrayOutputStream baos = doOutboundSecurity(outSecurityProperties, sourceDocument);

        SecurityProperties inSecurityProperties = new SecurityProperties();
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

        SecurityProperties outSecurityProperties = new SecurityProperties();
        outSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
        outSecurityProperties.setEncryptionUser("receiver");
        outSecurityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
        outSecurityProperties.setSignatureUser("transmitter");
        outSecurityProperties.setTokenUser("transmitter");
        outSecurityProperties.setUsernameTokenPasswordType(Constants.UsernameTokenPasswordType.PASSWORD_NONE);
        outSecurityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());

        outSecurityProperties.addSignaturePart(new SecurePart(Constants.TAG_wsu_Timestamp.getLocalPart(), Constants.TAG_wsu_Timestamp.getNamespaceURI(), SecurePart.Modifier.Element));
        outSecurityProperties.addSignaturePart(new SecurePart(Constants.TAG_soap_Body_LocalName, Constants.NS_SOAP11, SecurePart.Modifier.Element));
        outSecurityProperties.addSignaturePart(new SecurePart(Constants.TAG_wsse_UsernameToken.getLocalPart(), Constants.TAG_wsse_UsernameToken.getNamespaceURI(), SecurePart.Modifier.Element));
        //outSecurityProperties.addEncryptionPart(new SecurePart(Constants.TAG_wsu_Timestamp.getLocalPart(), Constants.TAG_wsu_Timestamp.getNamespaceURI(), SecurePart.Modifier.Element));
        //outSecurityProperties.addEncryptionPart(new SecurePart(Constants.TAG_wsu_Created.getLocalPart(), Constants.TAG_wsu_Created.getNamespaceURI(), SecurePart.Modifier.Element));
        //outSecurityProperties.addEncryptionPart(new SecurePart(Constants.TAG_wsu_Expires.getLocalPart(), Constants.TAG_wsu_Expires.getNamespaceURI(), SecurePart.Modifier.Content));
        outSecurityProperties.addEncryptionPart(new SecurePart(Constants.TAG_soap_Body_LocalName, Constants.NS_SOAP11, SecurePart.Modifier.Content));
        Constants.Action[] actions = new Constants.Action[]{Constants.Action.USERNAMETOKEN, Constants.Action.TIMESTAMP, Constants.Action.ENCRYPT, Constants.Action.SIGNATURE};
        outSecurityProperties.setOutAction(actions);

        InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
        ByteArrayOutputStream baos = doOutboundSecurity(outSecurityProperties, sourceDocument);

        SecurityProperties inSecurityProperties = new SecurityProperties();
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

        SecurityProperties outSecurityProperties = new SecurityProperties();
        outSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
        outSecurityProperties.setEncryptionUser("receiver");
        outSecurityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
        outSecurityProperties.setSignatureUser("transmitter");
        outSecurityProperties.setTokenUser("transmitter");
        outSecurityProperties.setUsernameTokenPasswordType(Constants.UsernameTokenPasswordType.PASSWORD_NONE);
        outSecurityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());

        outSecurityProperties.addSignaturePart(new SecurePart(Constants.TAG_wsu_Timestamp.getLocalPart(), Constants.TAG_wsu_Timestamp.getNamespaceURI(), SecurePart.Modifier.Element));
        outSecurityProperties.addSignaturePart(new SecurePart(Constants.TAG_soap_Body_LocalName, Constants.NS_SOAP11, SecurePart.Modifier.Element));
        //outSecurityProperties.addSignaturePart(new SecurePart(Constants.TAG_wsse_UsernameToken.getLocalPart(), Constants.TAG_wsse_UsernameToken.getNamespaceURI(), SecurePart.Modifier.Element));
        //outSecurityProperties.addEncryptionPart(new SecurePart(Constants.TAG_wsu_Timestamp.getLocalPart(), Constants.TAG_wsu_Timestamp.getNamespaceURI(), SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(Constants.TAG_wsu_Created.getLocalPart(), Constants.TAG_wsu_Created.getNamespaceURI(), SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(Constants.TAG_wsu_Expires.getLocalPart(), Constants.TAG_wsu_Expires.getNamespaceURI(), SecurePart.Modifier.Content));
        outSecurityProperties.addEncryptionPart(new SecurePart(Constants.TAG_soap_Body_LocalName, Constants.NS_SOAP11, SecurePart.Modifier.Content));
        Constants.Action[] actions = new Constants.Action[]{Constants.Action.USERNAMETOKEN, Constants.Action.TIMESTAMP, Constants.Action.SIGNATURE, Constants.Action.ENCRYPT};
        outSecurityProperties.setOutAction(actions);

        InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
        ByteArrayOutputStream baos = doOutboundSecurity(outSecurityProperties, sourceDocument);

        SecurityProperties inSecurityProperties = new SecurityProperties();
        inSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
        inSecurityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
        inSecurityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());

        PolicyEnforcerFactory policyEnforcerFactory = PolicyEnforcerFactory.newInstance(this.getClass().getClassLoader().getResource("testdata/wsdl/testTransportBindingBasicAuthenticationIncludeTimestampAndSignedUsernameSupportingTokenPolicy.wsdl"));
        PolicyEnforcer policyEnforcer = policyEnforcerFactory.newPolicyEnforcer(null);
        inSecurityProperties.addInputProcessor(new PolicyInputProcessor(policyEnforcer, null));

        HttpsTokenSecurityEvent httpsTokenSecurityEvent = new HttpsTokenSecurityEvent(SecurityEvent.Event.TransportToken);
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

        SecurityProperties outSecurityProperties = new SecurityProperties();
        outSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
        outSecurityProperties.setEncryptionUser("receiver");
        outSecurityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
        outSecurityProperties.setSignatureUser("transmitter");
        outSecurityProperties.setTokenUser("transmitter");
        outSecurityProperties.setUsernameTokenPasswordType(Constants.UsernameTokenPasswordType.PASSWORD_NONE);
        outSecurityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());

        outSecurityProperties.addSignaturePart(new SecurePart(Constants.TAG_wsu_Timestamp.getLocalPart(), Constants.TAG_wsu_Timestamp.getNamespaceURI(), SecurePart.Modifier.Element));
        outSecurityProperties.addSignaturePart(new SecurePart(Constants.TAG_soap_Body_LocalName, Constants.NS_SOAP11, SecurePart.Modifier.Element));
        //outSecurityProperties.addSignaturePart(new SecurePart(Constants.TAG_wsse_UsernameToken.getLocalPart(), Constants.TAG_wsse_UsernameToken.getNamespaceURI(), SecurePart.Modifier.Element));
        //outSecurityProperties.addEncryptionPart(new SecurePart(Constants.TAG_wsu_Timestamp.getLocalPart(), Constants.TAG_wsu_Timestamp.getNamespaceURI(), SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(Constants.TAG_wsu_Created.getLocalPart(), Constants.TAG_wsu_Created.getNamespaceURI(), SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(Constants.TAG_wsu_Expires.getLocalPart(), Constants.TAG_wsu_Expires.getNamespaceURI(), SecurePart.Modifier.Content));
        outSecurityProperties.addEncryptionPart(new SecurePart(Constants.TAG_soap_Body_LocalName, Constants.NS_SOAP11, SecurePart.Modifier.Content));
        Constants.Action[] actions = new Constants.Action[]{Constants.Action.USERNAMETOKEN, Constants.Action.TIMESTAMP, Constants.Action.SIGNATURE, Constants.Action.ENCRYPT};
        outSecurityProperties.setOutAction(actions);

        InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
        ByteArrayOutputStream baos = doOutboundSecurity(outSecurityProperties, sourceDocument);

        SecurityProperties inSecurityProperties = new SecurityProperties();
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

        SecurityProperties outSecurityProperties = new SecurityProperties();
        outSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
        outSecurityProperties.setEncryptionUser("receiver");
        outSecurityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
        outSecurityProperties.setSignatureUser("transmitter");
        outSecurityProperties.setTokenUser("transmitter");
        outSecurityProperties.setUsernameTokenPasswordType(Constants.UsernameTokenPasswordType.PASSWORD_NONE);
        outSecurityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());

        outSecurityProperties.addSignaturePart(new SecurePart(Constants.TAG_wsu_Timestamp.getLocalPart(), Constants.TAG_wsu_Timestamp.getNamespaceURI(), SecurePart.Modifier.Element));
        outSecurityProperties.addSignaturePart(new SecurePart(Constants.TAG_soap_Body_LocalName, Constants.NS_SOAP11, SecurePart.Modifier.Element));
        //outSecurityProperties.addSignaturePart(new SecurePart(Constants.TAG_wsse_UsernameToken.getLocalPart(), Constants.TAG_wsse_UsernameToken.getNamespaceURI(), SecurePart.Modifier.Element));
        //outSecurityProperties.addEncryptionPart(new SecurePart(Constants.TAG_wsu_Timestamp.getLocalPart(), Constants.TAG_wsu_Timestamp.getNamespaceURI(), SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(Constants.TAG_wsu_Created.getLocalPart(), Constants.TAG_wsu_Created.getNamespaceURI(), SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(Constants.TAG_wsu_Expires.getLocalPart(), Constants.TAG_wsu_Expires.getNamespaceURI(), SecurePart.Modifier.Content));
        outSecurityProperties.addEncryptionPart(new SecurePart(Constants.TAG_soap_Body_LocalName, Constants.NS_SOAP11, SecurePart.Modifier.Content));
        Constants.Action[] actions = new Constants.Action[]{Constants.Action.USERNAMETOKEN, Constants.Action.TIMESTAMP, Constants.Action.SIGNATURE, Constants.Action.ENCRYPT};
        outSecurityProperties.setOutAction(actions);

        InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
        ByteArrayOutputStream baos = doOutboundSecurity(outSecurityProperties, sourceDocument);

        SecurityProperties inSecurityProperties = new SecurityProperties();
        inSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
        inSecurityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
        inSecurityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());

        PolicyEnforcerFactory policyEnforcerFactory = PolicyEnforcerFactory.newInstance(this.getClass().getClassLoader().getResource("testdata/wsdl/testTransportBindingHttpsClientAuthenticationIncludeTimestampAndSignedUsernameSupportingTokenPolicy.wsdl"));
        PolicyEnforcer policyEnforcer = policyEnforcerFactory.newPolicyEnforcer(null);
        inSecurityProperties.addInputProcessor(new PolicyInputProcessor(policyEnforcer, null));

        HttpsTokenSecurityEvent httpsTokenSecurityEvent = new HttpsTokenSecurityEvent(SecurityEvent.Event.TransportToken);
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
