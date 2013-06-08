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

import org.apache.wss4j.common.crypto.WSProviderConfig;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.saml.SAMLCallback;
import org.apache.wss4j.common.saml.SamlAssertionWrapper;
import org.apache.wss4j.common.saml.bean.SubjectBean;
import org.apache.wss4j.stax.WSSec;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.impl.InboundWSSecurityContextImpl;
import org.apache.wss4j.stax.securityToken.WSSecurityTokenConstants;
import org.apache.wss4j.stax.impl.securityToken.HttpsSecurityTokenImpl;
import org.apache.wss4j.stax.impl.securityToken.SamlSecurityTokenImpl;
import org.apache.wss4j.stax.impl.securityToken.UsernameSecurityTokenImpl;
import org.apache.wss4j.stax.impl.securityToken.X509SecurityTokenImpl;
import org.apache.wss4j.stax.securityEvent.*;
import org.apache.wss4j.stax.securityEvent.X509TokenSecurityEvent;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.config.Init;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;
import org.apache.xml.security.stax.ext.stax.XMLSecEventFactory;
import org.apache.xml.security.stax.impl.util.IDGenerator;
import org.apache.xml.security.stax.securityEvent.*;
import org.opensaml.common.SAMLVersion;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import javax.xml.namespace.QName;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;

public class InboundWSSecurityContextImplTest {

    @BeforeClass
    public void setUp() throws Exception {
        WSProviderConfig.init();
        Init.init(WSSec.class.getClassLoader().getResource("wss/wss-config.xml").toURI());
    }

    @Test
    public void testTokenIdentificationTransportSecurity() throws Exception {

        final List<SecurityEvent> securityEventList = generateTransportBindingSecurityEvents();

        Assert.assertEquals(securityEventList.size(), 9);

        for (int i = 0; i < securityEventList.size(); i++) {
            SecurityEvent securityEvent = securityEventList.get(i);
            if (securityEvent instanceof HttpsTokenSecurityEvent) {
                HttpsTokenSecurityEvent tokenSecurityEvent = (HttpsTokenSecurityEvent) securityEvent;
                Assert.assertEquals(tokenSecurityEvent.getSecurityToken().getTokenUsages().size(), 2);
                Assert.assertTrue(tokenSecurityEvent.getSecurityToken().getTokenUsages().contains(WSSecurityTokenConstants.TokenUsage_MainSignature));
                Assert.assertTrue(tokenSecurityEvent.getSecurityToken().getTokenUsages().contains(WSSecurityTokenConstants.TokenUsage_MainEncryption));
            } else if (securityEvent instanceof X509TokenSecurityEvent) {
                X509TokenSecurityEvent tokenSecurityEvent = (X509TokenSecurityEvent) securityEvent;
                Assert.assertEquals(tokenSecurityEvent.getSecurityToken().getTokenUsages().size(), 1);
                Assert.assertTrue(tokenSecurityEvent.getSecurityToken().getTokenUsages().contains(WSSecurityTokenConstants.TokenUsage_SignedEndorsingSupportingTokens));
            } else if (securityEvent instanceof UsernameTokenSecurityEvent) {
                UsernameTokenSecurityEvent tokenSecurityEvent = (UsernameTokenSecurityEvent) securityEvent;
                Assert.assertEquals(tokenSecurityEvent.getSecurityToken().getTokenUsages().size(), 1);
                Assert.assertTrue(tokenSecurityEvent.getSecurityToken().getTokenUsages().contains(WSSecurityTokenConstants.TokenUsage_SignedEncryptedSupportingTokens));
            }
        }
    }

    public List<SecurityEvent> generateTransportBindingSecurityEvents() throws Exception {

        final List<SecurityEvent> securityEventList = new LinkedList<SecurityEvent>();

        SecurityEventListener securityEventListener = new SecurityEventListener() {
            @Override
            public void registerSecurityEvent(SecurityEvent securityEvent) throws WSSecurityException {
                securityEventList.add(securityEvent);
            }
        };

        InboundWSSecurityContextImpl inboundWSSecurityContext = new InboundWSSecurityContextImpl();
        inboundWSSecurityContext.addSecurityEventListener(securityEventListener);
        inboundWSSecurityContext.put(WSSConstants.TRANSPORT_SECURITY_ACTIVE, Boolean.TRUE);

        HttpsTokenSecurityEvent httpsTokenSecurityEvent = new HttpsTokenSecurityEvent();
        httpsTokenSecurityEvent.setSecurityToken(
                new HttpsSecurityTokenImpl(
                        getX509Token(WSSecurityTokenConstants.X509V3Token).getX509Certificates()[0]));
        inboundWSSecurityContext.registerSecurityEvent(httpsTokenSecurityEvent);

        TimestampSecurityEvent timestampSecurityEvent = new TimestampSecurityEvent();
        inboundWSSecurityContext.registerSecurityEvent(timestampSecurityEvent);

        List<QName> timestampPath = new LinkedList<QName>();
        timestampPath.addAll(WSSConstants.WSSE_SECURITY_HEADER_PATH);
        timestampPath.add(WSSConstants.TAG_wsu_Timestamp);

        RequiredElementSecurityEvent timestampRequiredElementSecurityEvent = new RequiredElementSecurityEvent();
        timestampRequiredElementSecurityEvent.setElementPath(timestampPath);
        inboundWSSecurityContext.registerSecurityEvent(timestampRequiredElementSecurityEvent);

        List<QName> usernameTokenPath = new LinkedList<QName>();
        usernameTokenPath.addAll(WSSConstants.WSSE_SECURITY_HEADER_PATH);
        usernameTokenPath.add(WSSConstants.TAG_wsse_UsernameToken);

        XMLSecEvent usernameTokenXmlEvent = XMLSecEventFactory.createXmlSecStartElement(WSSConstants.TAG_wsse_UsernameToken, null, null);

        UsernameTokenSecurityEvent usernameTokenSecurityEvent = new UsernameTokenSecurityEvent();
        UsernameSecurityTokenImpl usernameSecurityToken = new UsernameSecurityTokenImpl(
                WSSConstants.UsernameTokenPasswordType.PASSWORD_DIGEST,
                "username", "password", new Date().toString(), null, new byte[10], 10L,
                null, IDGenerator.generateID(null), WSSecurityTokenConstants.KeyIdentifier_SecurityTokenDirectReference);
        usernameSecurityToken.setElementPath(usernameTokenPath);
        usernameSecurityToken.setXMLSecEvent(usernameTokenXmlEvent);
        usernameTokenSecurityEvent.setSecurityToken(usernameSecurityToken);
        inboundWSSecurityContext.registerSecurityEvent(usernameTokenSecurityEvent);

        List<QName> bstPath = new LinkedList<QName>();
        bstPath.addAll(WSSConstants.WSSE_SECURITY_HEADER_PATH);
        bstPath.add(WSSConstants.TAG_wsse_BinarySecurityToken);

        XMLSecEvent signedEndorsingSupportingTokenXmlEvent = XMLSecEventFactory.createXmlSecStartElement(WSSConstants.TAG_wsse_UsernameToken, null, null);

        X509TokenSecurityEvent x509TokenSecurityEvent = new X509TokenSecurityEvent();
        X509SecurityTokenImpl signedEndorsingSupportingToken = getX509Token(WSSecurityTokenConstants.X509V3Token);
        signedEndorsingSupportingToken.setElementPath(bstPath);
        signedEndorsingSupportingToken.setXMLSecEvent(signedEndorsingSupportingTokenXmlEvent);
        x509TokenSecurityEvent.setSecurityToken(signedEndorsingSupportingToken);
        signedEndorsingSupportingToken.addTokenUsage(WSSecurityTokenConstants.TokenUsage_Signature);
        inboundWSSecurityContext.registerSecurityEvent(x509TokenSecurityEvent);

        SignatureValueSecurityEvent signatureValueSecurityEvent = new SignatureValueSecurityEvent();
        inboundWSSecurityContext.registerSecurityEvent(signatureValueSecurityEvent);

        List<XMLSecurityConstants.ContentType> protectionOrder = new LinkedList<XMLSecurityConstants.ContentType>();
        protectionOrder.add(XMLSecurityConstants.ContentType.SIGNATURE);

        SignedElementSecurityEvent signedTimestampElementSecurityEvent = new SignedElementSecurityEvent(signedEndorsingSupportingToken, true, protectionOrder);
        signedTimestampElementSecurityEvent.setElementPath(timestampPath);
        inboundWSSecurityContext.registerSecurityEvent(signedTimestampElementSecurityEvent);

        SignedElementSecurityEvent signedBSTElementSecurityEvent = new SignedElementSecurityEvent(signedEndorsingSupportingToken, true, protectionOrder);
        signedBSTElementSecurityEvent.setElementPath(bstPath);
        signedBSTElementSecurityEvent.setXmlSecEvent(signedEndorsingSupportingTokenXmlEvent);
        inboundWSSecurityContext.registerSecurityEvent(signedBSTElementSecurityEvent);

        OperationSecurityEvent operationSecurityEvent = new OperationSecurityEvent();
        operationSecurityEvent.setOperation(new QName("definitions"));
        inboundWSSecurityContext.registerSecurityEvent(operationSecurityEvent);

        return securityEventList;
    }

    @Test
    public void testTokenIdentificationAsymmetricSecurity() throws Exception {

        final List<SecurityEvent> securityEventList = generateAsymmetricBindingSecurityEvents();

        boolean mainSignatureTokenOccured = false;
        boolean signedEndorsingSupportingTokenOccured = false;
        boolean signedEndorsingEncryptedSupportingTokenOccured = false;
        boolean supportingTokensOccured = false;
        boolean encryptedSupportingTokensOccured = false;
        boolean mainEncryptionTokenOccured = false;
        boolean usernameTokenOccured = false;
        Assert.assertEquals(securityEventList.size(), 34);
        int x509TokenIndex = 0;
        for (int i = 0; i < securityEventList.size(); i++) {
            SecurityEvent securityEvent = securityEventList.get(i);
            if (securityEvent instanceof X509TokenSecurityEvent && x509TokenIndex == 0) {
                x509TokenIndex++;
                X509TokenSecurityEvent tokenSecurityEvent = (X509TokenSecurityEvent) securityEvent;
                Assert.assertEquals(tokenSecurityEvent.getSecurityToken().getTokenUsages().size(), 1);
                Assert.assertTrue(tokenSecurityEvent.getSecurityToken().getTokenUsages().contains(WSSecurityTokenConstants.TokenUsage_MainEncryption));
                mainEncryptionTokenOccured = true;
            } else if (securityEvent instanceof X509TokenSecurityEvent && x509TokenIndex == 1) {
                x509TokenIndex++;
                X509TokenSecurityEvent tokenSecurityEvent = (X509TokenSecurityEvent) securityEvent;
                Assert.assertEquals(tokenSecurityEvent.getSecurityToken().getTokenUsages().size(), 1);
                Assert.assertTrue(tokenSecurityEvent.getSecurityToken().getTokenUsages().contains(WSSecurityTokenConstants.TokenUsage_SignedEndorsingSupportingTokens));
                signedEndorsingSupportingTokenOccured = true;
            } else if (securityEvent instanceof X509TokenSecurityEvent && x509TokenIndex == 2) {
                x509TokenIndex++;
                X509TokenSecurityEvent tokenSecurityEvent = (X509TokenSecurityEvent) securityEvent;
                Assert.assertEquals(tokenSecurityEvent.getSecurityToken().getTokenUsages().size(), 1);
                Assert.assertTrue(tokenSecurityEvent.getSecurityToken().getTokenUsages().contains(WSSecurityTokenConstants.TokenUsage_EncryptedSupportingTokens));
                encryptedSupportingTokensOccured = true;
            } else if (securityEvent instanceof X509TokenSecurityEvent && x509TokenIndex == 3) {
                x509TokenIndex++;
                X509TokenSecurityEvent tokenSecurityEvent = (X509TokenSecurityEvent) securityEvent;
                Assert.assertEquals(tokenSecurityEvent.getSecurityToken().getTokenUsages().size(), 1);
                Assert.assertTrue(tokenSecurityEvent.getSecurityToken().getTokenUsages().contains(WSSecurityTokenConstants.TokenUsage_SupportingTokens));
                supportingTokensOccured = true;
            } else if (securityEvent instanceof X509TokenSecurityEvent && x509TokenIndex == 4) {
                x509TokenIndex++;
                X509TokenSecurityEvent tokenSecurityEvent = (X509TokenSecurityEvent) securityEvent;
                Assert.assertEquals(tokenSecurityEvent.getSecurityToken().getTokenUsages().size(), 1);
                Assert.assertTrue(tokenSecurityEvent.getSecurityToken().getTokenUsages().contains(WSSecurityTokenConstants.TokenUsage_SignedEndorsingEncryptedSupportingTokens));
                signedEndorsingEncryptedSupportingTokenOccured = true;
            } else if (securityEvent instanceof X509TokenSecurityEvent && x509TokenIndex == 5) {
                x509TokenIndex++;
                X509TokenSecurityEvent tokenSecurityEvent = (X509TokenSecurityEvent) securityEvent;
                Assert.assertEquals(tokenSecurityEvent.getSecurityToken().getTokenUsages().size(), 1);
                Assert.assertTrue(tokenSecurityEvent.getSecurityToken().getTokenUsages().contains(WSSecurityTokenConstants.TokenUsage_MainSignature));
                mainSignatureTokenOccured = true;
            } else if (securityEvent instanceof UsernameTokenSecurityEvent) {
                UsernameTokenSecurityEvent tokenSecurityEvent = (UsernameTokenSecurityEvent) securityEvent;
                Assert.assertEquals(tokenSecurityEvent.getSecurityToken().getTokenUsages().size(), 1);
                Assert.assertTrue(tokenSecurityEvent.getSecurityToken().getTokenUsages().contains(WSSecurityTokenConstants.TokenUsage_SignedEncryptedSupportingTokens));
                usernameTokenOccured = true;
            }
        }

        Assert.assertTrue(mainSignatureTokenOccured);
        Assert.assertTrue(mainEncryptionTokenOccured);
        Assert.assertTrue(signedEndorsingSupportingTokenOccured);
        Assert.assertTrue(signedEndorsingEncryptedSupportingTokenOccured);
        Assert.assertTrue(supportingTokensOccured);
        Assert.assertTrue(encryptedSupportingTokensOccured);
        Assert.assertTrue(usernameTokenOccured);
    }

    public List<SecurityEvent> generateAsymmetricBindingSecurityEvents() throws Exception {
        final List<SecurityEvent> securityEventList = new LinkedList<SecurityEvent>();

        SecurityEventListener securityEventListener = new SecurityEventListener() {
            @Override
            public void registerSecurityEvent(SecurityEvent securityEvent) throws WSSecurityException {
                securityEventList.add(securityEvent);
            }
        };

        InboundWSSecurityContextImpl inboundWSSecurityContext = new InboundWSSecurityContextImpl();
        inboundWSSecurityContext.addSecurityEventListener(securityEventListener);

        TimestampSecurityEvent timestampSecurityEvent = new TimestampSecurityEvent();
        inboundWSSecurityContext.registerSecurityEvent(timestampSecurityEvent);

        List<QName> timestampPath = new LinkedList<QName>();
        timestampPath.addAll(WSSConstants.WSSE_SECURITY_HEADER_PATH);
        timestampPath.add(WSSConstants.TAG_wsu_Timestamp);

        RequiredElementSecurityEvent timestampRequiredElementSecurityEvent = new RequiredElementSecurityEvent();
        timestampRequiredElementSecurityEvent.setElementPath(timestampPath);
        inboundWSSecurityContext.registerSecurityEvent(timestampRequiredElementSecurityEvent);

        List<QName> bstPath = new LinkedList<QName>();
        bstPath.addAll(WSSConstants.WSSE_SECURITY_HEADER_PATH);
        bstPath.add(WSSConstants.TAG_wsse_BinarySecurityToken);

        XMLSecEvent recipientTokenXmlEvent = XMLSecEventFactory.createXmlSecStartElement(WSSConstants.TAG_wsse_UsernameToken, null, null);

        X509TokenSecurityEvent recipientX509TokenSecurityEvent = new X509TokenSecurityEvent();
        X509SecurityTokenImpl recipientToken = getX509Token(WSSecurityTokenConstants.X509V3Token);
        recipientX509TokenSecurityEvent.setSecurityToken(recipientToken);
        recipientToken.setElementPath(bstPath);
        recipientToken.setXMLSecEvent(recipientTokenXmlEvent);
        recipientToken.addTokenUsage(WSSecurityTokenConstants.TokenUsage_Encryption);
        inboundWSSecurityContext.registerSecurityEvent(recipientX509TokenSecurityEvent);

        List<XMLSecurityConstants.ContentType> protectionOrder = new LinkedList<XMLSecurityConstants.ContentType>();
        protectionOrder.add(XMLSecurityConstants.ContentType.ENCRYPTION);
        protectionOrder.add(XMLSecurityConstants.ContentType.SIGNATURE);

        List<QName> signaturePath = new LinkedList<QName>();
        signaturePath.addAll(WSSConstants.WSSE_SECURITY_HEADER_PATH);
        signaturePath.add(WSSConstants.TAG_dsig_Signature);

        EncryptedElementSecurityEvent signatureEncryptedElementSecurityEvent = new EncryptedElementSecurityEvent(recipientToken, true, protectionOrder);
        signatureEncryptedElementSecurityEvent.setElementPath(signaturePath);
        inboundWSSecurityContext.registerSecurityEvent(signatureEncryptedElementSecurityEvent);

        List<QName> usernameTokenPath = new LinkedList<QName>();
        usernameTokenPath.addAll(WSSConstants.WSSE_SECURITY_HEADER_PATH);
        usernameTokenPath.add(WSSConstants.TAG_wsse_UsernameToken);

        XMLSecEvent usernameTokenXmlEvent = XMLSecEventFactory.createXmlSecStartElement(WSSConstants.TAG_wsse_UsernameToken, null, null);

        EncryptedElementSecurityEvent usernameEncryptedElementSecurityEvent = new EncryptedElementSecurityEvent(recipientToken, true, protectionOrder);
        usernameEncryptedElementSecurityEvent.setElementPath(usernameTokenPath);
        usernameEncryptedElementSecurityEvent.setXmlSecEvent(usernameTokenXmlEvent);
        inboundWSSecurityContext.registerSecurityEvent(usernameEncryptedElementSecurityEvent);

        XMLSecEvent signedEndorsingEncryptedTokenXmlEvent = XMLSecEventFactory.createXmlSecStartElement(WSSConstants.TAG_wsse_UsernameToken, null, null);

        EncryptedElementSecurityEvent signedEndorsedEncryptedTokenEncryptedElementSecurityEvent = new EncryptedElementSecurityEvent(recipientToken, true, protectionOrder);
        signedEndorsedEncryptedTokenEncryptedElementSecurityEvent.setElementPath(bstPath);
        signedEndorsedEncryptedTokenEncryptedElementSecurityEvent.setXmlSecEvent(signedEndorsingEncryptedTokenXmlEvent);
        inboundWSSecurityContext.registerSecurityEvent(signedEndorsedEncryptedTokenEncryptedElementSecurityEvent);

        XMLSecEvent encryptedSupportingTokenXmlEvent = XMLSecEventFactory.createXmlSecStartElement(WSSConstants.TAG_wsse_UsernameToken, null, null);

        EncryptedElementSecurityEvent encryptedSupportingTokenEncryptedElementSecurityEvent = new EncryptedElementSecurityEvent(recipientToken, true, protectionOrder);
        encryptedSupportingTokenEncryptedElementSecurityEvent.setElementPath(bstPath);
        encryptedSupportingTokenEncryptedElementSecurityEvent.setXmlSecEvent(encryptedSupportingTokenXmlEvent);
        inboundWSSecurityContext.registerSecurityEvent(encryptedSupportingTokenEncryptedElementSecurityEvent);

        UsernameTokenSecurityEvent usernameTokenSecurityEvent = new UsernameTokenSecurityEvent();
        UsernameSecurityTokenImpl usernameSecurityToken = new UsernameSecurityTokenImpl(
                WSSConstants.UsernameTokenPasswordType.PASSWORD_DIGEST,
                "username", "password", new Date().toString(), null, new byte[10], 10L,
                null, IDGenerator.generateID(null), WSSecurityTokenConstants.KeyIdentifier_SecurityTokenDirectReference);
        usernameSecurityToken.setElementPath(usernameTokenPath);
        usernameSecurityToken.setXMLSecEvent(usernameTokenXmlEvent);
        usernameTokenSecurityEvent.setSecurityToken(usernameSecurityToken);
        inboundWSSecurityContext.registerSecurityEvent(usernameTokenSecurityEvent);

        XMLSecEvent signedEndorsingTokenXmlEvent = XMLSecEventFactory.createXmlSecStartElement(WSSConstants.TAG_wsse_UsernameToken, null, null);

        X509TokenSecurityEvent signedEndorsingSupporting509TokenSecurityEvent = new X509TokenSecurityEvent();
        X509SecurityTokenImpl signedEndorsingSupportingToken = getX509Token(WSSecurityTokenConstants.X509V3Token);
        signedEndorsingSupporting509TokenSecurityEvent.setSecurityToken(signedEndorsingSupportingToken);
        signedEndorsingSupportingToken.setElementPath(bstPath);
        signedEndorsingSupportingToken.setXMLSecEvent(signedEndorsingTokenXmlEvent);
        inboundWSSecurityContext.registerSecurityEvent(signedEndorsingSupporting509TokenSecurityEvent);

        X509TokenSecurityEvent encryptedSupporting509TokenSecurityEvent = new X509TokenSecurityEvent();
        X509SecurityTokenImpl encryptedSupportingToken = getX509Token(WSSecurityTokenConstants.X509V3Token);
        encryptedSupporting509TokenSecurityEvent.setSecurityToken(encryptedSupportingToken);
        encryptedSupportingToken.setElementPath(bstPath);
        encryptedSupportingToken.setXMLSecEvent(encryptedSupportingTokenXmlEvent);
        inboundWSSecurityContext.registerSecurityEvent(encryptedSupporting509TokenSecurityEvent);

        X509TokenSecurityEvent supporting509TokenSecurityEvent = new X509TokenSecurityEvent();
        X509SecurityTokenImpl supportingToken = getX509Token(WSSecurityTokenConstants.X509V3Token);
        supporting509TokenSecurityEvent.setSecurityToken(supportingToken);
        supportingToken.setElementPath(bstPath);
        inboundWSSecurityContext.registerSecurityEvent(supporting509TokenSecurityEvent);

        X509TokenSecurityEvent signedEndorsingEncryptedSupporting509TokenSecurityEvent = new X509TokenSecurityEvent();
        X509SecurityTokenImpl signedEndorsingEncryptedSupportingToken = getX509Token(WSSecurityTokenConstants.X509V3Token);
        signedEndorsingEncryptedSupporting509TokenSecurityEvent.setSecurityToken(signedEndorsingEncryptedSupportingToken);
        signedEndorsingEncryptedSupportingToken.setElementPath(bstPath);
        signedEndorsingEncryptedSupportingToken.setXMLSecEvent(signedEndorsingEncryptedTokenXmlEvent);
        inboundWSSecurityContext.registerSecurityEvent(signedEndorsingEncryptedSupporting509TokenSecurityEvent);

        XMLSecEvent initiatorTokenXmlEvent = XMLSecEventFactory.createXmlSecStartElement(WSSConstants.TAG_wsse_UsernameToken, null, null);

        X509TokenSecurityEvent initiator509TokenSecurityEvent = new X509TokenSecurityEvent();
        X509SecurityTokenImpl initiatorToken = getX509Token(WSSecurityTokenConstants.X509V3Token);
        initiator509TokenSecurityEvent.setSecurityToken(initiatorToken);
        initiatorToken.setElementPath(bstPath);
        initiatorToken.setXMLSecEvent(initiatorTokenXmlEvent);
        inboundWSSecurityContext.registerSecurityEvent(initiator509TokenSecurityEvent);

        initiator509TokenSecurityEvent = new X509TokenSecurityEvent();
        initiator509TokenSecurityEvent.setSecurityToken(initiatorToken);
        initiatorToken.addTokenUsage(WSSecurityTokenConstants.TokenUsage_Signature);
        inboundWSSecurityContext.registerSecurityEvent(initiator509TokenSecurityEvent);

        SignatureValueSecurityEvent signatureValueSecurityEvent = new SignatureValueSecurityEvent();
        inboundWSSecurityContext.registerSecurityEvent(signatureValueSecurityEvent);

        SignedElementSecurityEvent signedTimestampElementSecurityEvent = new SignedElementSecurityEvent(initiatorToken, true, protectionOrder);
        signedTimestampElementSecurityEvent.setElementPath(timestampPath);
        inboundWSSecurityContext.registerSecurityEvent(signedTimestampElementSecurityEvent);

        SignedElementSecurityEvent signedUsernameTokenElementSecurityEvent = new SignedElementSecurityEvent(initiatorToken, true, protectionOrder);
        signedUsernameTokenElementSecurityEvent.setElementPath(usernameTokenPath);
        signedUsernameTokenElementSecurityEvent.setXmlSecEvent(usernameTokenXmlEvent);
        inboundWSSecurityContext.registerSecurityEvent(signedUsernameTokenElementSecurityEvent);

        SignedElementSecurityEvent bstElementSecurityEvent = new SignedElementSecurityEvent(initiatorToken, true, protectionOrder);
        bstElementSecurityEvent.setElementPath(bstPath);
        bstElementSecurityEvent.setXmlSecEvent(signedEndorsingTokenXmlEvent);
        inboundWSSecurityContext.registerSecurityEvent(bstElementSecurityEvent);

        bstElementSecurityEvent = new SignedElementSecurityEvent(initiatorToken, true, protectionOrder);
        bstElementSecurityEvent.setElementPath(bstPath);
        bstElementSecurityEvent.setXmlSecEvent(signedEndorsingEncryptedTokenXmlEvent);
        inboundWSSecurityContext.registerSecurityEvent(bstElementSecurityEvent);

        bstElementSecurityEvent = new SignedElementSecurityEvent(initiatorToken, true, protectionOrder);
        bstElementSecurityEvent.setElementPath(bstPath);
        bstElementSecurityEvent.setXmlSecEvent(initiatorTokenXmlEvent);
        inboundWSSecurityContext.registerSecurityEvent(bstElementSecurityEvent);

        List<QName> header1Path = new LinkedList<QName>();
        header1Path.addAll(WSSConstants.SOAP_11_HEADER_PATH);
        header1Path.add(new QName("x", "Header1", "x"));

        SignedPartSecurityEvent header1SignedPartSecurityEvent = new SignedPartSecurityEvent(initiatorToken, true, protectionOrder);
        header1SignedPartSecurityEvent.setElementPath(header1Path);
        inboundWSSecurityContext.registerSecurityEvent(header1SignedPartSecurityEvent);

        List<QName> header2Path = new LinkedList<QName>();
        header2Path.addAll(WSSConstants.SOAP_11_HEADER_PATH);
        header2Path.add(new QName("x", "Header1", "x"));

        SignedPartSecurityEvent header2SignedPartSecurityEvent = new SignedPartSecurityEvent(initiatorToken, true, protectionOrder);
        header2SignedPartSecurityEvent.setElementPath(header2Path);
        inboundWSSecurityContext.registerSecurityEvent(header2SignedPartSecurityEvent);

        List<QName> bodyPath = new LinkedList<QName>();
        bodyPath.addAll(WSSConstants.SOAP_11_BODY_PATH);

        SignedPartSecurityEvent bodySignedPartSecurityEvent = new SignedPartSecurityEvent(initiatorToken, true, protectionOrder);
        bodySignedPartSecurityEvent.setElementPath(bodyPath);
        inboundWSSecurityContext.registerSecurityEvent(bodySignedPartSecurityEvent);

        signedEndorsingSupporting509TokenSecurityEvent = new X509TokenSecurityEvent();
        signedEndorsingSupporting509TokenSecurityEvent.setSecurityToken(signedEndorsingSupportingToken);
        signedEndorsingSupportingToken.addTokenUsage(WSSecurityTokenConstants.TokenUsage_Signature);
        inboundWSSecurityContext.registerSecurityEvent(signedEndorsingSupporting509TokenSecurityEvent);

        SignatureValueSecurityEvent signature2ValueSecurityEvent = new SignatureValueSecurityEvent();
        inboundWSSecurityContext.registerSecurityEvent(signature2ValueSecurityEvent);

        SignedElementSecurityEvent signatureElementSecurityEvent = new SignedElementSecurityEvent(signedEndorsingSupportingToken, true, protectionOrder);
        signatureElementSecurityEvent.setElementPath(signaturePath);
        inboundWSSecurityContext.registerSecurityEvent(signatureElementSecurityEvent);

        bstElementSecurityEvent = new SignedElementSecurityEvent(signedEndorsingSupportingToken, true, protectionOrder);
        bstElementSecurityEvent.setElementPath(bstPath);
        bstElementSecurityEvent.setXmlSecEvent(signedEndorsingTokenXmlEvent);
        inboundWSSecurityContext.registerSecurityEvent(bstElementSecurityEvent);

        signedEndorsingEncryptedSupporting509TokenSecurityEvent = new X509TokenSecurityEvent();
        signedEndorsingEncryptedSupporting509TokenSecurityEvent.setSecurityToken(signedEndorsingEncryptedSupportingToken);
        signedEndorsingEncryptedSupportingToken.addTokenUsage(WSSecurityTokenConstants.TokenUsage_Signature);
        inboundWSSecurityContext.registerSecurityEvent(signedEndorsingEncryptedSupporting509TokenSecurityEvent);

        signature2ValueSecurityEvent = new SignatureValueSecurityEvent();
        inboundWSSecurityContext.registerSecurityEvent(signature2ValueSecurityEvent);

        signatureElementSecurityEvent = new SignedElementSecurityEvent(signedEndorsingEncryptedSupportingToken, true, protectionOrder);
        signatureElementSecurityEvent.setElementPath(signaturePath);
        inboundWSSecurityContext.registerSecurityEvent(signatureElementSecurityEvent);

        bstElementSecurityEvent = new SignedElementSecurityEvent(signedEndorsingEncryptedSupportingToken, true, protectionOrder);
        bstElementSecurityEvent.setElementPath(bstPath);
        bstElementSecurityEvent.setXmlSecEvent(signedEndorsingEncryptedTokenXmlEvent);
        inboundWSSecurityContext.registerSecurityEvent(bstElementSecurityEvent);

        EncryptedPartSecurityEvent bodyEncryptedPartSecurityEvent = new EncryptedPartSecurityEvent(recipientToken, true, protectionOrder);
        bodyEncryptedPartSecurityEvent.setElementPath(bodyPath);
        inboundWSSecurityContext.registerSecurityEvent(bodyEncryptedPartSecurityEvent);

        EncryptedPartSecurityEvent header2EncryptedPartSecurityEvent = new EncryptedPartSecurityEvent(recipientToken, true, protectionOrder);
        header2EncryptedPartSecurityEvent.setElementPath(header2Path);
        inboundWSSecurityContext.registerSecurityEvent(header2EncryptedPartSecurityEvent);

        OperationSecurityEvent operationSecurityEvent = new OperationSecurityEvent();
        operationSecurityEvent.setOperation(new QName("definitions"));
        inboundWSSecurityContext.registerSecurityEvent(operationSecurityEvent);
        return securityEventList;
    }

    @Test
    public void testTokenIdentificationSymmetricSecurity() throws Exception {

        final List<SecurityEvent> securityEventList = generateSymmetricBindingSecurityEvents();

        Assert.assertEquals(securityEventList.size(), 22);

        for (int i = 0; i < securityEventList.size(); i++) {
            SecurityEvent securityEvent = securityEventList.get(i);
            if (securityEvent instanceof X509TokenSecurityEvent) {
                X509TokenSecurityEvent tokenSecurityEvent = (X509TokenSecurityEvent) securityEvent;
                Assert.assertEquals(tokenSecurityEvent.getSecurityToken().getTokenUsages().size(), 1);
                Assert.assertTrue(tokenSecurityEvent.getSecurityToken().getTokenUsages().contains(WSSecurityTokenConstants.TokenUsage_SignedEndorsingSupportingTokens));
            } else if (securityEvent instanceof UsernameTokenSecurityEvent) {
                UsernameTokenSecurityEvent tokenSecurityEvent = (UsernameTokenSecurityEvent) securityEvent;
                Assert.assertEquals(tokenSecurityEvent.getSecurityToken().getTokenUsages().size(), 1);
                Assert.assertTrue(tokenSecurityEvent.getSecurityToken().getTokenUsages().contains(WSSecurityTokenConstants.TokenUsage_SignedEncryptedSupportingTokens));
            } else if (securityEvent instanceof SamlTokenSecurityEvent) {
                SamlTokenSecurityEvent tokenSecurityEvent = (SamlTokenSecurityEvent) securityEvent;
                Assert.assertEquals(tokenSecurityEvent.getSecurityToken().getTokenUsages().size(), 2);
                Assert.assertTrue(tokenSecurityEvent.getSecurityToken().getTokenUsages().contains(WSSecurityTokenConstants.TokenUsage_MainSignature));
                Assert.assertTrue(tokenSecurityEvent.getSecurityToken().getTokenUsages().contains(WSSecurityTokenConstants.TokenUsage_MainEncryption));
            }
        }
    }

    public List<SecurityEvent> generateSymmetricBindingSecurityEvents() throws Exception {
        final List<SecurityEvent> securityEventList = new LinkedList<SecurityEvent>();

        SecurityEventListener securityEventListener = new SecurityEventListener() {
            @Override
            public void registerSecurityEvent(SecurityEvent securityEvent) throws WSSecurityException {
                securityEventList.add(securityEvent);
            }
        };

        InboundWSSecurityContextImpl inboundWSSecurityContext = new InboundWSSecurityContextImpl();
        inboundWSSecurityContext.addSecurityEventListener(securityEventListener);

        TimestampSecurityEvent timestampSecurityEvent = new TimestampSecurityEvent();
        inboundWSSecurityContext.registerSecurityEvent(timestampSecurityEvent);

        List<QName> timestampPath = new LinkedList<QName>();
        timestampPath.addAll(WSSConstants.WSSE_SECURITY_HEADER_PATH);
        timestampPath.add(WSSConstants.TAG_wsu_Timestamp);

        RequiredElementSecurityEvent timestampRequiredElementSecurityEvent = new RequiredElementSecurityEvent();
        timestampRequiredElementSecurityEvent.setElementPath(timestampPath);
        inboundWSSecurityContext.registerSecurityEvent(timestampRequiredElementSecurityEvent);

        List<QName> samlTokenPath = new LinkedList<QName>();
        samlTokenPath.addAll(WSSConstants.WSSE_SECURITY_HEADER_PATH);
        samlTokenPath.add(WSSConstants.TAG_saml2_Assertion);

        XMLSecEvent samlTokenXmlEvent = XMLSecEventFactory.createXmlSecStartElement(WSSConstants.TAG_wsse_UsernameToken, null, null);

        SAMLCallback samlCallback = new SAMLCallback();
        samlCallback.setSamlVersion(SAMLVersion.VERSION_20);
        samlCallback.setIssuer("xs:anyURI");
        SubjectBean subjectBean = new SubjectBean();
        samlCallback.setSubject(subjectBean);
        SamlAssertionWrapper samlAssertionWrapper = new SamlAssertionWrapper(samlCallback);

        SamlSecurityTokenImpl samlSecurityToken = new SamlSecurityTokenImpl(
                samlAssertionWrapper, getX509Token(WSSecurityTokenConstants.X509V3Token), null, null, WSSecurityTokenConstants.KeyIdentifier_X509KeyIdentifier,
                null);
        samlSecurityToken.setElementPath(samlTokenPath);
        samlSecurityToken.setXMLSecEvent(samlTokenXmlEvent);
        samlSecurityToken.addTokenUsage(WSSecurityTokenConstants.TokenUsage_Encryption);
        SamlTokenSecurityEvent samlTokenSecurityEvent = new SamlTokenSecurityEvent();
        samlTokenSecurityEvent.setSecurityToken(samlSecurityToken);
        inboundWSSecurityContext.registerSecurityEvent(samlTokenSecurityEvent);

        List<XMLSecurityConstants.ContentType> protectionOrder = new LinkedList<XMLSecurityConstants.ContentType>();
        protectionOrder.add(XMLSecurityConstants.ContentType.ENCRYPTION);
        protectionOrder.add(XMLSecurityConstants.ContentType.SIGNATURE);

        List<QName> usernamePath = new LinkedList<QName>();
        usernamePath.addAll(WSSConstants.WSSE_SECURITY_HEADER_PATH);
        usernamePath.add(WSSConstants.TAG_wsse_UsernameToken);

        XMLSecEvent usernameTokenXmlEvent = XMLSecEventFactory.createXmlSecStartElement(WSSConstants.TAG_wsse_UsernameToken, null, null);

        EncryptedElementSecurityEvent usernameEncryptedElementSecurityEvent = new EncryptedElementSecurityEvent(samlSecurityToken, true, protectionOrder);
        usernameEncryptedElementSecurityEvent.setElementPath(usernamePath);
        usernameEncryptedElementSecurityEvent.setXmlSecEvent(usernameTokenXmlEvent);
        inboundWSSecurityContext.registerSecurityEvent(usernameEncryptedElementSecurityEvent);

        List<QName> usernameTokenPath = new LinkedList<QName>();
        usernameTokenPath.addAll(WSSConstants.WSSE_SECURITY_HEADER_PATH);
        usernameTokenPath.add(WSSConstants.TAG_wsse_UsernameToken);

        UsernameTokenSecurityEvent usernameTokenSecurityEvent = new UsernameTokenSecurityEvent();
        UsernameSecurityTokenImpl usernameSecurityToken = new UsernameSecurityTokenImpl(
                WSSConstants.UsernameTokenPasswordType.PASSWORD_DIGEST,
                "username", "password", new Date().toString(), null, new byte[10], 10L,
                null, IDGenerator.generateID(null), WSSecurityTokenConstants.KeyIdentifier_SecurityTokenDirectReference);
        usernameSecurityToken.setElementPath(usernamePath);
        usernameSecurityToken.setXMLSecEvent(usernameTokenXmlEvent);
        usernameTokenSecurityEvent.setSecurityToken(usernameSecurityToken);
        inboundWSSecurityContext.registerSecurityEvent(usernameTokenSecurityEvent);

        List<QName> signaturePath = new LinkedList<QName>();
        signaturePath.addAll(WSSConstants.WSSE_SECURITY_HEADER_PATH);
        signaturePath.add(WSSConstants.TAG_dsig_Signature);

        EncryptedElementSecurityEvent signatureEncryptedElementSecurityEvent = new EncryptedElementSecurityEvent(samlSecurityToken, true, protectionOrder);
        signatureEncryptedElementSecurityEvent.setElementPath(signaturePath);
        inboundWSSecurityContext.registerSecurityEvent(signatureEncryptedElementSecurityEvent);

        samlSecurityToken.addTokenUsage(WSSecurityTokenConstants.TokenUsage_Signature);
        samlTokenSecurityEvent = new SamlTokenSecurityEvent();
        samlTokenSecurityEvent.setSecurityToken(samlSecurityToken);
        inboundWSSecurityContext.registerSecurityEvent(samlTokenSecurityEvent);

        SignatureValueSecurityEvent signatureValueSecurityEvent = new SignatureValueSecurityEvent();
        inboundWSSecurityContext.registerSecurityEvent(signatureValueSecurityEvent);

        SignedElementSecurityEvent signedTimestampElementSecurityEvent = new SignedElementSecurityEvent(samlSecurityToken, true, protectionOrder);
        signedTimestampElementSecurityEvent.setElementPath(timestampPath);
        inboundWSSecurityContext.registerSecurityEvent(signedTimestampElementSecurityEvent);

        SignedElementSecurityEvent signedUsernameTokenElementSecurityEvent = new SignedElementSecurityEvent(samlSecurityToken, true, protectionOrder);
        signedUsernameTokenElementSecurityEvent.setElementPath(usernameTokenPath);
        signedUsernameTokenElementSecurityEvent.setXmlSecEvent(usernameTokenXmlEvent);
        inboundWSSecurityContext.registerSecurityEvent(signedUsernameTokenElementSecurityEvent);

        List<QName> bstPath = new LinkedList<QName>();
        bstPath.addAll(WSSConstants.WSSE_SECURITY_HEADER_PATH);
        bstPath.add(WSSConstants.TAG_wsse_BinarySecurityToken);

        XMLSecEvent bstTokenXmlEvent = XMLSecEventFactory.createXmlSecStartElement(WSSConstants.TAG_wsse_UsernameToken, null, null);

        SignedElementSecurityEvent bstElementSecurityEvent = new SignedElementSecurityEvent(samlSecurityToken, true, protectionOrder);
        bstElementSecurityEvent.setElementPath(bstPath);
        bstElementSecurityEvent.setXmlSecEvent(bstTokenXmlEvent);
        inboundWSSecurityContext.registerSecurityEvent(bstElementSecurityEvent);

        SignedElementSecurityEvent samlTokenElementSecurityEvent = new SignedElementSecurityEvent(samlSecurityToken, true, protectionOrder);
        samlTokenElementSecurityEvent.setElementPath(samlTokenPath);
        samlTokenElementSecurityEvent.setXmlSecEvent(samlTokenXmlEvent);
        inboundWSSecurityContext.registerSecurityEvent(samlTokenElementSecurityEvent);

        List<QName> header1Path = new LinkedList<QName>();
        header1Path.addAll(WSSConstants.SOAP_11_HEADER_PATH);
        header1Path.add(new QName("x", "Header1", "x"));

        SignedPartSecurityEvent header1SignedPartSecurityEvent = new SignedPartSecurityEvent(samlSecurityToken, true, protectionOrder);
        header1SignedPartSecurityEvent.setElementPath(header1Path);
        inboundWSSecurityContext.registerSecurityEvent(header1SignedPartSecurityEvent);

        List<QName> header2Path = new LinkedList<QName>();
        header2Path.addAll(WSSConstants.SOAP_11_HEADER_PATH);
        header2Path.add(new QName("x", "Header1", "x"));

        SignedPartSecurityEvent header2SignedPartSecurityEvent = new SignedPartSecurityEvent(samlSecurityToken, true, protectionOrder);
        header2SignedPartSecurityEvent.setElementPath(header2Path);
        inboundWSSecurityContext.registerSecurityEvent(header2SignedPartSecurityEvent);

        List<QName> bodyPath = new LinkedList<QName>();
        bodyPath.addAll(WSSConstants.SOAP_11_BODY_PATH);

        SignedPartSecurityEvent bodySignedPartSecurityEvent = new SignedPartSecurityEvent(samlSecurityToken, true, protectionOrder);
        bodySignedPartSecurityEvent.setElementPath(bodyPath);
        inboundWSSecurityContext.registerSecurityEvent(bodySignedPartSecurityEvent);

        X509TokenSecurityEvent x509TokenSecurityEvent = new X509TokenSecurityEvent();
        X509SecurityTokenImpl signedEndorsingSupportingToken = getX509Token(WSSecurityTokenConstants.X509V3Token);
        x509TokenSecurityEvent.setSecurityToken(signedEndorsingSupportingToken);
        signedEndorsingSupportingToken.setElementPath(bstPath);
        signedEndorsingSupportingToken.setXMLSecEvent(bstTokenXmlEvent);
        signedEndorsingSupportingToken.addTokenUsage(WSSecurityTokenConstants.TokenUsage_Signature);
        inboundWSSecurityContext.registerSecurityEvent(x509TokenSecurityEvent);

        SignatureValueSecurityEvent signature2ValueSecurityEvent = new SignatureValueSecurityEvent();
        inboundWSSecurityContext.registerSecurityEvent(signature2ValueSecurityEvent);

        SignedElementSecurityEvent signatureElementSecurityEvent = new SignedElementSecurityEvent(signedEndorsingSupportingToken, true, protectionOrder);
        signatureElementSecurityEvent.setElementPath(signaturePath);
        inboundWSSecurityContext.registerSecurityEvent(signatureElementSecurityEvent);

        bstElementSecurityEvent = new SignedElementSecurityEvent(signedEndorsingSupportingToken, true, protectionOrder);
        bstElementSecurityEvent.setElementPath(bstPath);
        bstElementSecurityEvent.setXmlSecEvent(bstTokenXmlEvent);
        inboundWSSecurityContext.registerSecurityEvent(bstElementSecurityEvent);

        EncryptedPartSecurityEvent header2EncryptedPartSecurityEvent = new EncryptedPartSecurityEvent(samlSecurityToken, true, protectionOrder);
        header2EncryptedPartSecurityEvent.setElementPath(header2Path);
        inboundWSSecurityContext.registerSecurityEvent(header2EncryptedPartSecurityEvent);

        EncryptedPartSecurityEvent bodyEncryptedPartSecurityEvent = new EncryptedPartSecurityEvent(samlSecurityToken, true, protectionOrder);
        bodyEncryptedPartSecurityEvent.setElementPath(bodyPath);
        inboundWSSecurityContext.registerSecurityEvent(bodyEncryptedPartSecurityEvent);

        OperationSecurityEvent operationSecurityEvent = new OperationSecurityEvent();
        operationSecurityEvent.setOperation(new QName("definitions"));
        inboundWSSecurityContext.registerSecurityEvent(operationSecurityEvent);
        return securityEventList;
    }

    private X509SecurityTokenImpl getX509Token(WSSecurityTokenConstants.TokenType tokenType) throws Exception {

        final KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(this.getClass().getClassLoader().getResourceAsStream("transmitter.jks"), "default".toCharArray());

        X509SecurityTokenImpl x509SecurityToken =
                new X509SecurityTokenImpl(tokenType, null, null, null, IDGenerator.generateID(null),
                        WSSecurityTokenConstants.KeyIdentifier_ThumbprintIdentifier, null, true) {

            @Override
            protected String getAlias() throws WSSecurityException {
                return "transmitter";
            }
        };
        x509SecurityToken.setSecretKey("", keyStore.getKey("transmitter", "default".toCharArray()));
        x509SecurityToken.setPublicKey(keyStore.getCertificate("transmitter").getPublicKey());

        Certificate[] certificates;
        try {
            certificates = keyStore.getCertificateChain("transmitter");
        } catch (Exception e) {
            throw new XMLSecurityException(e.getMessage(), e);
        }

        X509Certificate[] x509Certificates = new X509Certificate[certificates.length];
        for (int i = 0; i < certificates.length; i++) {
            Certificate certificate = certificates[i];
            x509Certificates[i] = (X509Certificate) certificate;
        }
        x509SecurityToken.setX509Certificates(x509Certificates);
        return x509SecurityToken;
    }
}
