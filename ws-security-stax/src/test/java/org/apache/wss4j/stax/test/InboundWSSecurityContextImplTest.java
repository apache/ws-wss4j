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

import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.LinkedList;
import java.util.List;

import javax.xml.namespace.QName;

import org.apache.wss4j.common.crypto.WSProviderConfig;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.saml.SAMLCallback;
import org.apache.wss4j.common.saml.SamlAssertionWrapper;
import org.apache.wss4j.common.saml.bean.SubjectBean;
import org.apache.wss4j.common.saml.bean.Version;
import org.apache.wss4j.common.util.DateUtil;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.impl.InboundWSSecurityContextImpl;
import org.apache.wss4j.stax.impl.securityToken.HttpsSecurityTokenImpl;
import org.apache.wss4j.stax.impl.securityToken.SamlSecurityTokenImpl;
import org.apache.wss4j.stax.impl.securityToken.UsernameSecurityTokenImpl;
import org.apache.wss4j.stax.impl.securityToken.X509SecurityTokenImpl;
import org.apache.wss4j.stax.securityEvent.EncryptedPartSecurityEvent;
import org.apache.wss4j.stax.securityEvent.HttpsTokenSecurityEvent;
import org.apache.wss4j.stax.securityEvent.OperationSecurityEvent;
import org.apache.wss4j.stax.securityEvent.RequiredElementSecurityEvent;
import org.apache.wss4j.stax.securityEvent.SamlTokenSecurityEvent;
import org.apache.wss4j.stax.securityEvent.SignatureConfirmationSecurityEvent;
import org.apache.wss4j.stax.securityEvent.SignedPartSecurityEvent;
import org.apache.wss4j.stax.securityEvent.TimestampSecurityEvent;
import org.apache.wss4j.stax.securityEvent.UsernameTokenSecurityEvent;
import org.apache.wss4j.stax.securityEvent.X509TokenSecurityEvent;
import org.apache.wss4j.stax.securityToken.WSSecurityTokenConstants;
import org.apache.wss4j.stax.setup.WSSec;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.config.Init;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;
import org.apache.xml.security.stax.ext.stax.XMLSecEventFactory;
import org.apache.xml.security.stax.impl.util.IDGenerator;
import org.apache.xml.security.stax.securityEvent.EncryptedElementSecurityEvent;
import org.apache.xml.security.stax.securityEvent.SecurityEvent;
import org.apache.xml.security.stax.securityEvent.SecurityEventListener;
import org.apache.xml.security.stax.securityEvent.SignatureValueSecurityEvent;
import org.apache.xml.security.stax.securityEvent.SignedElementSecurityEvent;
import org.junit.BeforeClass;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class InboundWSSecurityContextImplTest {

    @BeforeClass
    public static void setUp() throws Exception {
        WSProviderConfig.init();
        Init.init(WSSec.class.getClassLoader().getResource("wss/wss-config.xml").toURI(), WSSec.class);
    }

    @Test
    public void testTokenIdentificationTransportSecurity() throws Exception {

        final List<SecurityEvent> securityEventList = generateTransportBindingSecurityEvents();

        assertEquals(securityEventList.size(), 11);

        for (int i = 0; i < securityEventList.size(); i++) {
            SecurityEvent securityEvent = securityEventList.get(i);
            if (securityEvent instanceof HttpsTokenSecurityEvent) {
                HttpsTokenSecurityEvent tokenSecurityEvent = (HttpsTokenSecurityEvent) securityEvent;
                assertEquals(tokenSecurityEvent.getSecurityToken().getTokenUsages().size(), 2);
                assertTrue(tokenSecurityEvent.getSecurityToken().getTokenUsages().contains(WSSecurityTokenConstants.TOKENUSAGE_MAIN_SIGNATURE));
                assertTrue(tokenSecurityEvent.getSecurityToken().getTokenUsages().contains(WSSecurityTokenConstants.TOKENUSAGE_MAIN_ENCRYPTION));
            } else if (securityEvent instanceof X509TokenSecurityEvent) {
                X509TokenSecurityEvent tokenSecurityEvent = (X509TokenSecurityEvent) securityEvent;
                assertEquals(tokenSecurityEvent.getSecurityToken().getTokenUsages().size(), 1);
                assertTrue(tokenSecurityEvent.getSecurityToken().getTokenUsages().contains(WSSecurityTokenConstants.TOKENUSAGE_SIGNED_ENDORSING_ENCRYPTED_SUPPORTING_TOKENS));
            } else if (securityEvent instanceof UsernameTokenSecurityEvent) {
                UsernameTokenSecurityEvent tokenSecurityEvent = (UsernameTokenSecurityEvent) securityEvent;
                assertEquals(tokenSecurityEvent.getSecurityToken().getTokenUsages().size(), 1);
                assertTrue(tokenSecurityEvent.getSecurityToken().getTokenUsages().contains(WSSecurityTokenConstants.TOKENUSAGE_SIGNED_ENCRYPTED_SUPPORTING_TOKENS));
            }
        }
    }

    public List<SecurityEvent> generateTransportBindingSecurityEvents() throws Exception {

        final List<SecurityEvent> securityEventList = new LinkedList<>();

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

        List<QName> timestampPath = new LinkedList<>();
        timestampPath.addAll(WSSConstants.WSSE_SECURITY_HEADER_PATH);
        timestampPath.add(WSSConstants.TAG_WSU_TIMESTAMP);

        RequiredElementSecurityEvent timestampRequiredElementSecurityEvent = new RequiredElementSecurityEvent();
        timestampRequiredElementSecurityEvent.setElementPath(timestampPath);
        inboundWSSecurityContext.registerSecurityEvent(timestampRequiredElementSecurityEvent);

        List<QName> usernameTokenPath = new LinkedList<>();
        usernameTokenPath.addAll(WSSConstants.WSSE_SECURITY_HEADER_PATH);
        usernameTokenPath.add(WSSConstants.TAG_WSSE_USERNAME_TOKEN);

        XMLSecEvent usernameTokenXmlEvent = XMLSecEventFactory.createXmlSecStartElement(WSSConstants.TAG_WSSE_USERNAME_TOKEN, null, null);

        UsernameTokenSecurityEvent usernameTokenSecurityEvent = new UsernameTokenSecurityEvent();
        ZonedDateTime now = ZonedDateTime.now(ZoneOffset.UTC);
        String created = DateUtil.getDateTimeFormatter(true).format(now);
        UsernameSecurityTokenImpl usernameSecurityToken = new UsernameSecurityTokenImpl(
                WSSConstants.UsernameTokenPasswordType.PASSWORD_TEXT,
                "username", "password", created, null, new byte[10], 10L,
                null, IDGenerator.generateID(null), WSSecurityTokenConstants.KEYIDENTIFIER_SECURITY_TOKEN_DIRECT_REFERENCE);
        usernameSecurityToken.setElementPath(usernameTokenPath);
        usernameSecurityToken.setXMLSecEvent(usernameTokenXmlEvent);
        usernameTokenSecurityEvent.setSecurityToken(usernameSecurityToken);
        inboundWSSecurityContext.registerSecurityEvent(usernameTokenSecurityEvent);

        SignatureConfirmationSecurityEvent signatureConfirmationSecurityEvent = new SignatureConfirmationSecurityEvent();
        inboundWSSecurityContext.registerSecurityEvent(signatureConfirmationSecurityEvent);

        List<QName> scPath = new LinkedList<>();
        scPath.addAll(WSSConstants.WSSE_SECURITY_HEADER_PATH);
        scPath.add(WSSConstants.TAG_WSSE11_SIG_CONF);

        RequiredElementSecurityEvent scRequiredElementSecurityEvent = new RequiredElementSecurityEvent();
        scRequiredElementSecurityEvent.setElementPath(scPath);
        inboundWSSecurityContext.registerSecurityEvent(scRequiredElementSecurityEvent);

        List<QName> bstPath = new LinkedList<>();
        bstPath.addAll(WSSConstants.WSSE_SECURITY_HEADER_PATH);
        bstPath.add(WSSConstants.TAG_WSSE_BINARY_SECURITY_TOKEN);

        XMLSecEvent signedEndorsingSupportingTokenXmlEvent = XMLSecEventFactory.createXmlSecStartElement(WSSConstants.TAG_WSSE_USERNAME_TOKEN, null, null);

        X509TokenSecurityEvent x509TokenSecurityEvent = new X509TokenSecurityEvent();
        X509SecurityTokenImpl signedEndorsingEncryptedSupportingToken = getX509Token(WSSecurityTokenConstants.X509V3Token);
        signedEndorsingEncryptedSupportingToken.setElementPath(bstPath);
        signedEndorsingEncryptedSupportingToken.setXMLSecEvent(signedEndorsingSupportingTokenXmlEvent);
        x509TokenSecurityEvent.setSecurityToken(signedEndorsingEncryptedSupportingToken);
        signedEndorsingEncryptedSupportingToken.addTokenUsage(WSSecurityTokenConstants.TokenUsage_Signature);
        inboundWSSecurityContext.registerSecurityEvent(x509TokenSecurityEvent);

        SignatureValueSecurityEvent signatureValueSecurityEvent = new SignatureValueSecurityEvent();
        inboundWSSecurityContext.registerSecurityEvent(signatureValueSecurityEvent);

        List<XMLSecurityConstants.ContentType> protectionOrder = new LinkedList<>();
        protectionOrder.add(XMLSecurityConstants.ContentType.SIGNATURE);

        SignedElementSecurityEvent signedTimestampElementSecurityEvent = new SignedElementSecurityEvent(signedEndorsingEncryptedSupportingToken, true, protectionOrder);
        signedTimestampElementSecurityEvent.setElementPath(timestampPath);
        inboundWSSecurityContext.registerSecurityEvent(signedTimestampElementSecurityEvent);

        SignedElementSecurityEvent signedBSTElementSecurityEvent = new SignedElementSecurityEvent(signedEndorsingEncryptedSupportingToken, true, protectionOrder);
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
        assertEquals(securityEventList.size(), 34);
        int x509TokenIndex = 0;
        for (int i = 0; i < securityEventList.size(); i++) {
            SecurityEvent securityEvent = securityEventList.get(i);
            if (securityEvent instanceof X509TokenSecurityEvent && x509TokenIndex == 0) {
                x509TokenIndex++;
                X509TokenSecurityEvent tokenSecurityEvent = (X509TokenSecurityEvent) securityEvent;
                assertEquals(tokenSecurityEvent.getSecurityToken().getTokenUsages().size(), 1);
                assertTrue(tokenSecurityEvent.getSecurityToken().getTokenUsages().contains(WSSecurityTokenConstants.TOKENUSAGE_MAIN_ENCRYPTION));
                mainEncryptionTokenOccured = true;
            } else if (securityEvent instanceof X509TokenSecurityEvent && x509TokenIndex == 1) {
                x509TokenIndex++;
                X509TokenSecurityEvent tokenSecurityEvent = (X509TokenSecurityEvent) securityEvent;
                assertEquals(tokenSecurityEvent.getSecurityToken().getTokenUsages().size(), 1);
                assertTrue(tokenSecurityEvent.getSecurityToken().getTokenUsages().contains(WSSecurityTokenConstants.TOKENUSAGE_ENCRYPTED_SUPPORTING_TOKENS));
                signedEndorsingSupportingTokenOccured = true;
            } else if (securityEvent instanceof X509TokenSecurityEvent && x509TokenIndex == 2) {
                x509TokenIndex++;
                X509TokenSecurityEvent tokenSecurityEvent = (X509TokenSecurityEvent) securityEvent;
                assertEquals(tokenSecurityEvent.getSecurityToken().getTokenUsages().size(), 1);
                assertTrue(tokenSecurityEvent.getSecurityToken().getTokenUsages().contains(WSSecurityTokenConstants.TOKENUSAGE_SUPPORTING_TOKENS));
                encryptedSupportingTokensOccured = true;
            } else if (securityEvent instanceof X509TokenSecurityEvent && x509TokenIndex == 3) {
                x509TokenIndex++;
                X509TokenSecurityEvent tokenSecurityEvent = (X509TokenSecurityEvent) securityEvent;
                assertEquals(tokenSecurityEvent.getSecurityToken().getTokenUsages().size(), 1);
                assertTrue(tokenSecurityEvent.getSecurityToken().getTokenUsages().contains(WSSecurityTokenConstants.TOKENUSAGE_MAIN_SIGNATURE));
                supportingTokensOccured = true;
            } else if (securityEvent instanceof X509TokenSecurityEvent && x509TokenIndex == 4) {
                x509TokenIndex++;
                X509TokenSecurityEvent tokenSecurityEvent = (X509TokenSecurityEvent) securityEvent;
                assertEquals(tokenSecurityEvent.getSecurityToken().getTokenUsages().size(), 1);
                assertTrue(tokenSecurityEvent.getSecurityToken().getTokenUsages().contains(WSSecurityTokenConstants.TOKENUSAGE_SIGNED_ENDORSING_SUPPORTING_TOKENS));
                signedEndorsingEncryptedSupportingTokenOccured = true;
            } else if (securityEvent instanceof X509TokenSecurityEvent && x509TokenIndex == 5) {
                x509TokenIndex++;
                X509TokenSecurityEvent tokenSecurityEvent = (X509TokenSecurityEvent) securityEvent;
                assertEquals(tokenSecurityEvent.getSecurityToken().getTokenUsages().size(), 1);
                assertTrue(tokenSecurityEvent.getSecurityToken().getTokenUsages().contains(WSSecurityTokenConstants.TOKENUSAGE_SIGNED_ENDORSING_ENCRYPTED_SUPPORTING_TOKENS));
                mainSignatureTokenOccured = true;
            } else if (securityEvent instanceof UsernameTokenSecurityEvent) {
                UsernameTokenSecurityEvent tokenSecurityEvent = (UsernameTokenSecurityEvent) securityEvent;
                assertEquals(tokenSecurityEvent.getSecurityToken().getTokenUsages().size(), 1);
                assertTrue(tokenSecurityEvent.getSecurityToken().getTokenUsages().contains(WSSecurityTokenConstants.TOKENUSAGE_SIGNED_ENCRYPTED_SUPPORTING_TOKENS));
                usernameTokenOccured = true;
            }
        }

        assertTrue(mainSignatureTokenOccured);
        assertTrue(mainEncryptionTokenOccured);
        assertTrue(signedEndorsingSupportingTokenOccured);
        assertTrue(signedEndorsingEncryptedSupportingTokenOccured);
        assertTrue(supportingTokensOccured);
        assertTrue(encryptedSupportingTokensOccured);
        assertTrue(usernameTokenOccured);
    }

    public List<SecurityEvent> generateAsymmetricBindingSecurityEvents() throws Exception {
        final List<SecurityEvent> securityEventList = new LinkedList<>();

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

        List<QName> timestampPath = new LinkedList<>();
        timestampPath.addAll(WSSConstants.WSSE_SECURITY_HEADER_PATH);
        timestampPath.add(WSSConstants.TAG_WSU_TIMESTAMP);

        RequiredElementSecurityEvent timestampRequiredElementSecurityEvent = new RequiredElementSecurityEvent();
        timestampRequiredElementSecurityEvent.setElementPath(timestampPath);
        inboundWSSecurityContext.registerSecurityEvent(timestampRequiredElementSecurityEvent);

        SignatureConfirmationSecurityEvent signatureConfirmationSecurityEvent = new SignatureConfirmationSecurityEvent();
        inboundWSSecurityContext.registerSecurityEvent(signatureConfirmationSecurityEvent);

        List<QName> scPath = new LinkedList<>();
        scPath.addAll(WSSConstants.WSSE_SECURITY_HEADER_PATH);
        scPath.add(WSSConstants.TAG_WSSE11_SIG_CONF);

        RequiredElementSecurityEvent scRequiredElementSecurityEvent = new RequiredElementSecurityEvent();
        scRequiredElementSecurityEvent.setElementPath(scPath);
        inboundWSSecurityContext.registerSecurityEvent(scRequiredElementSecurityEvent);

        List<QName> bstPath = new LinkedList<>();
        bstPath.addAll(WSSConstants.WSSE_SECURITY_HEADER_PATH);
        bstPath.add(WSSConstants.TAG_WSSE_BINARY_SECURITY_TOKEN);

        XMLSecEvent recipientTokenXmlEvent = XMLSecEventFactory.createXmlSecStartElement(WSSConstants.TAG_WSSE_USERNAME_TOKEN, null, null);

        X509TokenSecurityEvent recipientX509TokenSecurityEvent = new X509TokenSecurityEvent();
        X509SecurityTokenImpl recipientToken = getX509Token(WSSecurityTokenConstants.X509V3Token);
        recipientX509TokenSecurityEvent.setSecurityToken(recipientToken);
        recipientToken.setElementPath(bstPath);
        recipientToken.setXMLSecEvent(recipientTokenXmlEvent);
        recipientToken.addTokenUsage(WSSecurityTokenConstants.TokenUsage_Encryption);
        inboundWSSecurityContext.registerSecurityEvent(recipientX509TokenSecurityEvent);

        List<XMLSecurityConstants.ContentType> protectionOrder = new LinkedList<>();
        protectionOrder.add(XMLSecurityConstants.ContentType.ENCRYPTION);
        protectionOrder.add(XMLSecurityConstants.ContentType.SIGNATURE);

        List<QName> signaturePath = new LinkedList<>();
        signaturePath.addAll(WSSConstants.WSSE_SECURITY_HEADER_PATH);
        signaturePath.add(WSSConstants.TAG_dsig_Signature);

        EncryptedElementSecurityEvent signatureEncryptedElementSecurityEvent = new EncryptedElementSecurityEvent(recipientToken, true, protectionOrder);
        signatureEncryptedElementSecurityEvent.setElementPath(signaturePath);
        inboundWSSecurityContext.registerSecurityEvent(signatureEncryptedElementSecurityEvent);

        List<QName> usernameTokenPath = new LinkedList<>();
        usernameTokenPath.addAll(WSSConstants.WSSE_SECURITY_HEADER_PATH);
        usernameTokenPath.add(WSSConstants.TAG_WSSE_USERNAME_TOKEN);

        XMLSecEvent usernameTokenXmlEvent = XMLSecEventFactory.createXmlSecStartElement(WSSConstants.TAG_WSSE_USERNAME_TOKEN, null, null);

        EncryptedElementSecurityEvent usernameEncryptedElementSecurityEvent = new EncryptedElementSecurityEvent(recipientToken, true, protectionOrder);
        usernameEncryptedElementSecurityEvent.setElementPath(usernameTokenPath);
        usernameEncryptedElementSecurityEvent.setXmlSecEvent(usernameTokenXmlEvent);
        inboundWSSecurityContext.registerSecurityEvent(usernameEncryptedElementSecurityEvent);

        XMLSecEvent signedEndorsingEncryptedTokenXmlEvent = XMLSecEventFactory.createXmlSecStartElement(WSSConstants.TAG_WSSE_USERNAME_TOKEN, null, null);

        EncryptedElementSecurityEvent signedEndorsedEncryptedTokenEncryptedElementSecurityEvent = new EncryptedElementSecurityEvent(recipientToken, true, protectionOrder);
        signedEndorsedEncryptedTokenEncryptedElementSecurityEvent.setElementPath(bstPath);
        signedEndorsedEncryptedTokenEncryptedElementSecurityEvent.setXmlSecEvent(signedEndorsingEncryptedTokenXmlEvent);
        inboundWSSecurityContext.registerSecurityEvent(signedEndorsedEncryptedTokenEncryptedElementSecurityEvent);

        XMLSecEvent encryptedSupportingTokenXmlEvent = XMLSecEventFactory.createXmlSecStartElement(WSSConstants.TAG_WSSE_USERNAME_TOKEN, null, null);

        EncryptedElementSecurityEvent encryptedSupportingTokenEncryptedElementSecurityEvent = new EncryptedElementSecurityEvent(recipientToken, true, protectionOrder);
        encryptedSupportingTokenEncryptedElementSecurityEvent.setElementPath(bstPath);
        encryptedSupportingTokenEncryptedElementSecurityEvent.setXmlSecEvent(encryptedSupportingTokenXmlEvent);
        inboundWSSecurityContext.registerSecurityEvent(encryptedSupportingTokenEncryptedElementSecurityEvent);

        UsernameTokenSecurityEvent usernameTokenSecurityEvent = new UsernameTokenSecurityEvent();
        ZonedDateTime now = ZonedDateTime.now(ZoneOffset.UTC);
        String created = DateUtil.getDateTimeFormatter(true).format(now);
        UsernameSecurityTokenImpl usernameSecurityToken = new UsernameSecurityTokenImpl(
                WSSConstants.UsernameTokenPasswordType.PASSWORD_TEXT,
                "username", "password", created, null, new byte[10], 10L,
                null, IDGenerator.generateID(null), WSSecurityTokenConstants.KEYIDENTIFIER_SECURITY_TOKEN_DIRECT_REFERENCE);
        usernameSecurityToken.setElementPath(usernameTokenPath);
        usernameSecurityToken.setXMLSecEvent(usernameTokenXmlEvent);
        usernameTokenSecurityEvent.setSecurityToken(usernameSecurityToken);
        inboundWSSecurityContext.registerSecurityEvent(usernameTokenSecurityEvent);

        XMLSecEvent signedEndorsingTokenXmlEvent = XMLSecEventFactory.createXmlSecStartElement(WSSConstants.TAG_WSSE_USERNAME_TOKEN, null, null);

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

        XMLSecEvent initiatorTokenXmlEvent = XMLSecEventFactory.createXmlSecStartElement(WSSConstants.TAG_WSSE_USERNAME_TOKEN, null, null);

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

        SignedElementSecurityEvent signedSCElementSecurityEvent = new SignedElementSecurityEvent(initiatorToken, true, protectionOrder);
        signedSCElementSecurityEvent.setElementPath(scPath);
        inboundWSSecurityContext.registerSecurityEvent(signedSCElementSecurityEvent);

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

        List<QName> header1Path = new LinkedList<>();
        header1Path.addAll(WSSConstants.SOAP_11_HEADER_PATH);
        header1Path.add(new QName("x", "Header1", "x"));

        SignedPartSecurityEvent header1SignedPartSecurityEvent = new SignedPartSecurityEvent(initiatorToken, true, protectionOrder);
        header1SignedPartSecurityEvent.setElementPath(header1Path);
        inboundWSSecurityContext.registerSecurityEvent(header1SignedPartSecurityEvent);

        List<QName> header2Path = new LinkedList<>();
        header2Path.addAll(WSSConstants.SOAP_11_HEADER_PATH);
        header2Path.add(new QName("x", "Header1", "x"));

        SignedPartSecurityEvent header2SignedPartSecurityEvent = new SignedPartSecurityEvent(initiatorToken, true, protectionOrder);
        header2SignedPartSecurityEvent.setElementPath(header2Path);
        inboundWSSecurityContext.registerSecurityEvent(header2SignedPartSecurityEvent);

        List<QName> bodyPath = new LinkedList<>();
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

        assertEquals(securityEventList.size(), 24);

        for (int i = 0; i < securityEventList.size(); i++) {
            SecurityEvent securityEvent = securityEventList.get(i);
            if (securityEvent instanceof X509TokenSecurityEvent) {
                X509TokenSecurityEvent tokenSecurityEvent = (X509TokenSecurityEvent) securityEvent;
                assertEquals(tokenSecurityEvent.getSecurityToken().getTokenUsages().size(), 1);
                assertTrue(tokenSecurityEvent.getSecurityToken().getTokenUsages().contains(WSSecurityTokenConstants.TOKENUSAGE_SIGNED_ENDORSING_SUPPORTING_TOKENS));
            } else if (securityEvent instanceof UsernameTokenSecurityEvent) {
                UsernameTokenSecurityEvent tokenSecurityEvent = (UsernameTokenSecurityEvent) securityEvent;
                assertEquals(tokenSecurityEvent.getSecurityToken().getTokenUsages().size(), 1);
                assertTrue(tokenSecurityEvent.getSecurityToken().getTokenUsages().contains(WSSecurityTokenConstants.TOKENUSAGE_SIGNED_ENCRYPTED_SUPPORTING_TOKENS));
            } else if (securityEvent instanceof SamlTokenSecurityEvent) {
                SamlTokenSecurityEvent tokenSecurityEvent = (SamlTokenSecurityEvent) securityEvent;
                assertEquals(tokenSecurityEvent.getSecurityToken().getTokenUsages().size(), 2);
                assertTrue(tokenSecurityEvent.getSecurityToken().getTokenUsages().contains(WSSecurityTokenConstants.TOKENUSAGE_MAIN_SIGNATURE));
                assertTrue(tokenSecurityEvent.getSecurityToken().getTokenUsages().contains(WSSecurityTokenConstants.TOKENUSAGE_MAIN_ENCRYPTION));
            }
        }
    }

    public List<SecurityEvent> generateSymmetricBindingSecurityEvents() throws Exception {
        final List<SecurityEvent> securityEventList = new LinkedList<>();

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

        List<QName> timestampPath = new LinkedList<>();
        timestampPath.addAll(WSSConstants.WSSE_SECURITY_HEADER_PATH);
        timestampPath.add(WSSConstants.TAG_WSU_TIMESTAMP);

        RequiredElementSecurityEvent timestampRequiredElementSecurityEvent = new RequiredElementSecurityEvent();
        timestampRequiredElementSecurityEvent.setElementPath(timestampPath);
        inboundWSSecurityContext.registerSecurityEvent(timestampRequiredElementSecurityEvent);

        SignatureConfirmationSecurityEvent signatureConfirmationSecurityEvent = new SignatureConfirmationSecurityEvent();
        inboundWSSecurityContext.registerSecurityEvent(signatureConfirmationSecurityEvent);

        List<QName> scPath = new LinkedList<>();
        scPath.addAll(WSSConstants.WSSE_SECURITY_HEADER_PATH);
        scPath.add(WSSConstants.TAG_WSSE11_SIG_CONF);

        RequiredElementSecurityEvent scRequiredElementSecurityEvent = new RequiredElementSecurityEvent();
        scRequiredElementSecurityEvent.setElementPath(scPath);
        inboundWSSecurityContext.registerSecurityEvent(scRequiredElementSecurityEvent);

        List<QName> samlTokenPath = new LinkedList<>();
        samlTokenPath.addAll(WSSConstants.WSSE_SECURITY_HEADER_PATH);
        samlTokenPath.add(WSSConstants.TAG_SAML2_ASSERTION);

        XMLSecEvent samlTokenXmlEvent = XMLSecEventFactory.createXmlSecStartElement(WSSConstants.TAG_WSSE_USERNAME_TOKEN, null, null);

        SAMLCallback samlCallback = new SAMLCallback();
        samlCallback.setSamlVersion(Version.SAML_20);
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

        List<XMLSecurityConstants.ContentType> protectionOrder = new LinkedList<>();
        protectionOrder.add(XMLSecurityConstants.ContentType.ENCRYPTION);
        protectionOrder.add(XMLSecurityConstants.ContentType.SIGNATURE);

        List<QName> usernamePath = new LinkedList<>();
        usernamePath.addAll(WSSConstants.WSSE_SECURITY_HEADER_PATH);
        usernamePath.add(WSSConstants.TAG_WSSE_USERNAME_TOKEN);

        XMLSecEvent usernameTokenXmlEvent = XMLSecEventFactory.createXmlSecStartElement(WSSConstants.TAG_WSSE_USERNAME_TOKEN, null, null);

        EncryptedElementSecurityEvent usernameEncryptedElementSecurityEvent = new EncryptedElementSecurityEvent(samlSecurityToken, true, protectionOrder);
        usernameEncryptedElementSecurityEvent.setElementPath(usernamePath);
        usernameEncryptedElementSecurityEvent.setXmlSecEvent(usernameTokenXmlEvent);
        inboundWSSecurityContext.registerSecurityEvent(usernameEncryptedElementSecurityEvent);

        List<QName> usernameTokenPath = new LinkedList<>();
        usernameTokenPath.addAll(WSSConstants.WSSE_SECURITY_HEADER_PATH);
        usernameTokenPath.add(WSSConstants.TAG_WSSE_USERNAME_TOKEN);

        UsernameTokenSecurityEvent usernameTokenSecurityEvent = new UsernameTokenSecurityEvent();
        ZonedDateTime now = ZonedDateTime.now(ZoneOffset.UTC);
        String created = DateUtil.getDateTimeFormatter(true).format(now);
        UsernameSecurityTokenImpl usernameSecurityToken = new UsernameSecurityTokenImpl(
                WSSConstants.UsernameTokenPasswordType.PASSWORD_TEXT,
                "username", "password", created, null, new byte[10], 10L,
                null, IDGenerator.generateID(null), WSSecurityTokenConstants.KEYIDENTIFIER_SECURITY_TOKEN_DIRECT_REFERENCE);
        usernameSecurityToken.setElementPath(usernamePath);
        usernameSecurityToken.setXMLSecEvent(usernameTokenXmlEvent);
        usernameTokenSecurityEvent.setSecurityToken(usernameSecurityToken);
        inboundWSSecurityContext.registerSecurityEvent(usernameTokenSecurityEvent);

        List<QName> signaturePath = new LinkedList<>();
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

        SignedElementSecurityEvent signedSCElementSecurityEvent = new SignedElementSecurityEvent(samlSecurityToken, true, protectionOrder);
        signedSCElementSecurityEvent.setElementPath(scPath);
        inboundWSSecurityContext.registerSecurityEvent(signedSCElementSecurityEvent);

        SignedElementSecurityEvent signedUsernameTokenElementSecurityEvent = new SignedElementSecurityEvent(samlSecurityToken, true, protectionOrder);
        signedUsernameTokenElementSecurityEvent.setElementPath(usernameTokenPath);
        signedUsernameTokenElementSecurityEvent.setXmlSecEvent(usernameTokenXmlEvent);
        inboundWSSecurityContext.registerSecurityEvent(signedUsernameTokenElementSecurityEvent);

        List<QName> bstPath = new LinkedList<>();
        bstPath.addAll(WSSConstants.WSSE_SECURITY_HEADER_PATH);
        bstPath.add(WSSConstants.TAG_WSSE_BINARY_SECURITY_TOKEN);

        XMLSecEvent bstTokenXmlEvent = XMLSecEventFactory.createXmlSecStartElement(WSSConstants.TAG_WSSE_USERNAME_TOKEN, null, null);

        SignedElementSecurityEvent bstElementSecurityEvent = new SignedElementSecurityEvent(samlSecurityToken, true, protectionOrder);
        bstElementSecurityEvent.setElementPath(bstPath);
        bstElementSecurityEvent.setXmlSecEvent(bstTokenXmlEvent);
        inboundWSSecurityContext.registerSecurityEvent(bstElementSecurityEvent);

        SignedElementSecurityEvent samlTokenElementSecurityEvent = new SignedElementSecurityEvent(samlSecurityToken, true, protectionOrder);
        samlTokenElementSecurityEvent.setElementPath(samlTokenPath);
        samlTokenElementSecurityEvent.setXmlSecEvent(samlTokenXmlEvent);
        inboundWSSecurityContext.registerSecurityEvent(samlTokenElementSecurityEvent);

        List<QName> header1Path = new LinkedList<>();
        header1Path.addAll(WSSConstants.SOAP_11_HEADER_PATH);
        header1Path.add(new QName("x", "Header1", "x"));

        SignedPartSecurityEvent header1SignedPartSecurityEvent = new SignedPartSecurityEvent(samlSecurityToken, true, protectionOrder);
        header1SignedPartSecurityEvent.setElementPath(header1Path);
        inboundWSSecurityContext.registerSecurityEvent(header1SignedPartSecurityEvent);

        List<QName> header2Path = new LinkedList<>();
        header2Path.addAll(WSSConstants.SOAP_11_HEADER_PATH);
        header2Path.add(new QName("x", "Header1", "x"));

        SignedPartSecurityEvent header2SignedPartSecurityEvent = new SignedPartSecurityEvent(samlSecurityToken, true, protectionOrder);
        header2SignedPartSecurityEvent.setElementPath(header2Path);
        inboundWSSecurityContext.registerSecurityEvent(header2SignedPartSecurityEvent);

        List<QName> bodyPath = new LinkedList<>();
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
        InputStream input = this.getClass().getClassLoader().getResourceAsStream("transmitter.jks");
        keyStore.load(input, "default".toCharArray());
        input.close();

        X509SecurityTokenImpl x509SecurityToken =
                new X509SecurityTokenImpl(tokenType, null, null, null, IDGenerator.generateID(null),
                        WSSecurityTokenConstants.KEYIDENTIFIER_THUMBPRINT_IDENTIFIER, null, true) {

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
            throw new XMLSecurityException(e);
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