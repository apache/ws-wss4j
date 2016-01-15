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

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

import javax.xml.namespace.QName;

import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.policy.stax.PolicyViolationException;
import org.apache.wss4j.policy.stax.enforcer.PolicyEnforcer;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.impl.securityToken.SecureConversationSecurityTokenImpl;
import org.apache.wss4j.stax.securityEvent.OperationSecurityEvent;
import org.apache.wss4j.stax.securityEvent.RequiredElementSecurityEvent;
import org.apache.wss4j.stax.securityEvent.SecurityContextTokenSecurityEvent;
import org.apache.wss4j.stax.securityEvent.SignedPartSecurityEvent;
import org.apache.wss4j.stax.securityEvent.TimestampSecurityEvent;
import org.apache.wss4j.stax.securityToken.WSSecurityTokenConstants;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.ext.stax.XMLSecEventFactory;
import org.apache.xml.security.stax.securityEvent.EncryptedElementSecurityEvent;
import org.junit.Assert;
import org.junit.Test;

public class SymmetricBindingTest extends AbstractPolicyTestBase {

    @Test
    public void testPolicy() throws Exception {
        String policyString =
                "<sp:SymmetricBinding xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\" xmlns:sp3=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200802\">\n" +
                        "<wsp:Policy xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">\n" +
                        "   <sp:AlgorithmSuite>\n" +
                        "       <wsp:Policy>\n" +
                        "           <sp:Basic256/>\n" +
                        "       </wsp:Policy>\n" +
                        "   </sp:AlgorithmSuite>\n" +
                        "<sp:IncludeTimestamp/>\n" +
                        "<sp:EncryptSignature/>\n" +
                        "<sp:OnlySignEntireHeadersAndBody/>\n" +
                        "</wsp:Policy>\n" +
                        "</sp:SymmetricBinding>";
        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);

        TimestampSecurityEvent timestampSecurityEvent = new TimestampSecurityEvent();
        policyEnforcer.registerSecurityEvent(timestampSecurityEvent);

        RequiredElementSecurityEvent requiredElementSecurityEvent = new RequiredElementSecurityEvent();
        List<QName> headerPath = new ArrayList<>();
        headerPath.addAll(WSSConstants.WSSE_SECURITY_HEADER_PATH);
        headerPath.add(WSSConstants.TAG_WSU_TIMESTAMP);
        requiredElementSecurityEvent.setElementPath(headerPath);
        policyEnforcer.registerSecurityEvent(requiredElementSecurityEvent);

        SecurityContextTokenSecurityEvent initiatorTokenSecurityEvent = new SecurityContextTokenSecurityEvent();
        SecureConversationSecurityTokenImpl securityToken =
                new SecureConversationSecurityTokenImpl(
                        null, "1", WSSecurityTokenConstants.KEYIDENTIFIER_SECURITY_TOKEN_DIRECT_REFERENCE);
        securityToken.addTokenUsage(WSSecurityTokenConstants.TOKENUSAGE_MAIN_SIGNATURE);
        initiatorTokenSecurityEvent.setSecurityToken(securityToken);
        policyEnforcer.registerSecurityEvent(initiatorTokenSecurityEvent);

        SecurityContextTokenSecurityEvent recipientTokenSecurityEvent = new SecurityContextTokenSecurityEvent();
        securityToken = new SecureConversationSecurityTokenImpl(
                null, "1", WSSecurityTokenConstants.KEYIDENTIFIER_SECURITY_TOKEN_DIRECT_REFERENCE);
        securityToken.addTokenUsage(WSSecurityTokenConstants.TOKENUSAGE_MAIN_ENCRYPTION);
        recipientTokenSecurityEvent.setSecurityToken(securityToken);
        policyEnforcer.registerSecurityEvent(recipientTokenSecurityEvent);

        List<XMLSecurityConstants.ContentType> protectionOrder = new LinkedList<>();
        protectionOrder.add(XMLSecurityConstants.ContentType.SIGNATURE);
        protectionOrder.add(XMLSecurityConstants.ContentType.ENCRYPTION);
        EncryptedElementSecurityEvent encryptedElementSecurityEvent = new EncryptedElementSecurityEvent(null, true, protectionOrder);
        headerPath = new ArrayList<>();
        headerPath.addAll(WSSConstants.WSSE_SECURITY_HEADER_PATH);
        headerPath.add(WSSConstants.TAG_dsig_Signature);
        encryptedElementSecurityEvent.setElementPath(headerPath);
        policyEnforcer.registerSecurityEvent(encryptedElementSecurityEvent);

        encryptedElementSecurityEvent = new EncryptedElementSecurityEvent(null, true, protectionOrder);
        headerPath = new ArrayList<>();
        headerPath.addAll(WSSConstants.WSSE_SECURITY_HEADER_PATH);
        headerPath.add(WSSConstants.TAG_WSSE11_SIG_CONF);
        encryptedElementSecurityEvent.setElementPath(headerPath);
        policyEnforcer.registerSecurityEvent(encryptedElementSecurityEvent);

        OperationSecurityEvent operationSecurityEvent = new OperationSecurityEvent();
        operationSecurityEvent.setOperation(new QName("definitions"));
        policyEnforcer.registerSecurityEvent(operationSecurityEvent);

        SignedPartSecurityEvent signedPartSecurityEvent = new SignedPartSecurityEvent(null, true, protectionOrder);
        signedPartSecurityEvent.setXmlSecEvent(XMLSecEventFactory.createXmlSecStartElement(WSSConstants.TAG_SOAP11_BODY, null, null));
        signedPartSecurityEvent.setElementPath(WSSConstants.SOAP_11_BODY_PATH);
        policyEnforcer.registerSecurityEvent(signedPartSecurityEvent);
        policyEnforcer.doFinal();
    }

    @Test
    public void testPolicyNotIncludeTimestamp() throws Exception {
        String policyString =
                "<sp:SymmetricBinding xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\" xmlns:sp3=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200802\">\n" +
                        "<wsp:Policy xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">\n" +
                        "   <sp:AlgorithmSuite>\n" +
                        "       <wsp:Policy>\n" +
                        "           <sp:Basic256/>\n" +
                        "       </wsp:Policy>\n" +
                        "   </sp:AlgorithmSuite>\n" +
                        "<sp:EncryptSignature/>\n" +
                        "<sp:ProtectTokens/>\n" +
                        "<sp:OnlySignEntireHeadersAndBody/>\n" +
                        "</wsp:Policy>\n" +
                        "</sp:SymmetricBinding>";
        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);

        SecurityContextTokenSecurityEvent initiatorTokenSecurityEvent = new SecurityContextTokenSecurityEvent();
        SecureConversationSecurityTokenImpl securityToken =
                new SecureConversationSecurityTokenImpl(
                        null, "1", WSSecurityTokenConstants.KEYIDENTIFIER_SECURITY_TOKEN_DIRECT_REFERENCE);
        securityToken.addTokenUsage(WSSecurityTokenConstants.TOKENUSAGE_MAIN_SIGNATURE);
        initiatorTokenSecurityEvent.setSecurityToken(securityToken);
        policyEnforcer.registerSecurityEvent(initiatorTokenSecurityEvent);

        SecurityContextTokenSecurityEvent recipientTokenSecurityEvent = new SecurityContextTokenSecurityEvent();
        securityToken = new SecureConversationSecurityTokenImpl(
                null, "1", WSSecurityTokenConstants.KEYIDENTIFIER_SECURITY_TOKEN_DIRECT_REFERENCE);
        securityToken.addTokenUsage(WSSecurityTokenConstants.TOKENUSAGE_MAIN_ENCRYPTION);
        recipientTokenSecurityEvent.setSecurityToken(securityToken);
        policyEnforcer.registerSecurityEvent(recipientTokenSecurityEvent);

        TimestampSecurityEvent timestampSecurityEvent = new TimestampSecurityEvent();
        policyEnforcer.registerSecurityEvent(timestampSecurityEvent);

        OperationSecurityEvent operationSecurityEvent = new OperationSecurityEvent();
        operationSecurityEvent.setOperation(new QName("definitions"));
        try {
            policyEnforcer.registerSecurityEvent(operationSecurityEvent);
            Assert.fail("Exception expected");
        } catch (WSSecurityException e) {
            Assert.assertTrue(e.getCause() instanceof PolicyViolationException);
            Assert.assertEquals(e.getCause().getMessage(),
                    "Timestamp must not be present");
            Assert.assertEquals(e.getFaultCode(), WSSecurityException.INVALID_SECURITY);
        }
    }

    @Test
    public void testPolicyWrongProtectionOrder() throws Exception {
        String policyString =
                "<sp:SymmetricBinding xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\" xmlns:sp3=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200802\">\n" +
                        "<wsp:Policy xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">\n" +
                        "   <sp:AlgorithmSuite>\n" +
                        "       <wsp:Policy>\n" +
                        "           <sp:Basic256/>\n" +
                        "       </wsp:Policy>\n" +
                        "   </sp:AlgorithmSuite>\n" +
                        "<sp:IncludeTimestamp/>\n" +
                        "<sp:EncryptBeforeSigning/>\n" +
                        "<sp:EncryptSignature/>\n" +
                        "<sp:ProtectTokens/>\n" +
                        "<sp:OnlySignEntireHeadersAndBody/>\n" +
                        "</wsp:Policy>\n" +
                        "</sp:SymmetricBinding>";
        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);
        SecurityContextTokenSecurityEvent SecurityContextTokenSecurityEvent = new SecurityContextTokenSecurityEvent();
        SecureConversationSecurityTokenImpl securityToken =
                new SecureConversationSecurityTokenImpl(
                        null, "1", WSSecurityTokenConstants.KEYIDENTIFIER_SECURITY_TOKEN_DIRECT_REFERENCE);
        securityToken.addTokenUsage(WSSecurityTokenConstants.TOKENUSAGE_MAIN_ENCRYPTION);
        SecurityContextTokenSecurityEvent.setSecurityToken(securityToken);
        policyEnforcer.registerSecurityEvent(SecurityContextTokenSecurityEvent);

        List<XMLSecurityConstants.ContentType> protectionOrder = new LinkedList<>();
        protectionOrder.add(XMLSecurityConstants.ContentType.SIGNATURE);
        protectionOrder.add(XMLSecurityConstants.ContentType.ENCRYPTION);
        SignedPartSecurityEvent signedPartSecurityEvent = new SignedPartSecurityEvent(null, true, protectionOrder);
        signedPartSecurityEvent.setElementPath(WSSConstants.SOAP_11_BODY_PATH);
        policyEnforcer.registerSecurityEvent(signedPartSecurityEvent);

        OperationSecurityEvent operationSecurityEvent = new OperationSecurityEvent();
        operationSecurityEvent.setOperation(new QName("definitions"));
        try {
            policyEnforcer.registerSecurityEvent(operationSecurityEvent);
            Assert.fail("Exception expected");
        } catch (WSSecurityException e) {
            Assert.assertTrue(e.getCause() instanceof PolicyViolationException);
            Assert.assertEquals(e.getCause().getMessage(),
                    "Policy enforces EncryptBeforeSigning but the /{http://schemas.xmlsoap.org/soap/envelope/}Envelope/{http://schemas.xmlsoap.org/soap/envelope/}Body was signed and then encrypted");
            Assert.assertEquals(e.getFaultCode(), WSSecurityException.INVALID_SECURITY);
        }
    }

    @Test
    public void testPolicySignatureNotEncrypted() throws Exception {
        String policyString =
                "<sp:SymmetricBinding xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\" xmlns:sp3=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200802\">\n" +
                        "<wsp:Policy xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">\n" +
                        "   <sp:AlgorithmSuite>\n" +
                        "       <wsp:Policy>\n" +
                        "           <sp:Basic256/>\n" +
                        "       </wsp:Policy>\n" +
                        "   </sp:AlgorithmSuite>\n" +
                        "<sp:IncludeTimestamp/>\n" +
                        "<sp:EncryptSignature/>\n" +
                        "<sp:ProtectTokens/>\n" +
                        "<sp:OnlySignEntireHeadersAndBody/>\n" +
                        "</wsp:Policy>\n" +
                        "</sp:SymmetricBinding>";
        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);
        TimestampSecurityEvent timestampSecurityEvent = new TimestampSecurityEvent();
        policyEnforcer.registerSecurityEvent(timestampSecurityEvent);

        SecurityContextTokenSecurityEvent initiatorTokenSecurityEvent = new SecurityContextTokenSecurityEvent();
        SecureConversationSecurityTokenImpl securityToken =
                new SecureConversationSecurityTokenImpl(
                        null, "1", WSSecurityTokenConstants.KEYIDENTIFIER_SECURITY_TOKEN_DIRECT_REFERENCE);
        securityToken.addTokenUsage(WSSecurityTokenConstants.TOKENUSAGE_MAIN_SIGNATURE);
        initiatorTokenSecurityEvent.setSecurityToken(securityToken);
        policyEnforcer.registerSecurityEvent(initiatorTokenSecurityEvent);

        SecurityContextTokenSecurityEvent recipientTokenSecurityEvent = new SecurityContextTokenSecurityEvent();
        securityToken = new SecureConversationSecurityTokenImpl(
                null, "1", WSSecurityTokenConstants.KEYIDENTIFIER_SECURITY_TOKEN_DIRECT_REFERENCE);
        securityToken.addTokenUsage(WSSecurityTokenConstants.TOKENUSAGE_MAIN_ENCRYPTION);
        recipientTokenSecurityEvent.setSecurityToken(securityToken);
        policyEnforcer.registerSecurityEvent(recipientTokenSecurityEvent);

        List<XMLSecurityConstants.ContentType> protectionOrder = new LinkedList<>();
        protectionOrder.add(XMLSecurityConstants.ContentType.SIGNATURE);
        protectionOrder.add(XMLSecurityConstants.ContentType.ENCRYPTION);
        EncryptedElementSecurityEvent encryptedElementSecurityEvent = new EncryptedElementSecurityEvent(null, false, protectionOrder);
        List<QName> headerPath = new ArrayList<>();
        headerPath.addAll(WSSConstants.WSSE_SECURITY_HEADER_PATH);
        headerPath.add(WSSConstants.TAG_dsig_Signature);
        encryptedElementSecurityEvent.setElementPath(headerPath);
        policyEnforcer.registerSecurityEvent(encryptedElementSecurityEvent);

        OperationSecurityEvent operationSecurityEvent = new OperationSecurityEvent();
        operationSecurityEvent.setOperation(new QName("definitions"));
        try {
            policyEnforcer.registerSecurityEvent(operationSecurityEvent);
            Assert.fail("Exception expected");
        } catch (WSSecurityException e) {
            Assert.assertEquals(e.getCause().getMessage(),
                    "Element /{http://schemas.xmlsoap.org/soap/envelope/}Envelope/{http://schemas.xmlsoap.org/soap/envelope/}Header/{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd}Security/{http://www.w3.org/2000/09/xmldsig#}Signature must be encrypted");
            Assert.assertEquals(e.getFaultCode(), WSSecurityException.INVALID_SECURITY);
        }
    }

    @Test
    public void testPolicyNotWholeBodySigned() throws Exception {
        String policyString =
                "<sp:SymmetricBinding xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\" xmlns:sp3=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200802\">\n" +
                        "<wsp:Policy xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">\n" +
                        "   <sp:AlgorithmSuite>\n" +
                        "       <wsp:Policy>\n" +
                        "           <sp:Basic256/>\n" +
                        "       </wsp:Policy>\n" +
                        "   </sp:AlgorithmSuite>\n" +
                        "<sp:IncludeTimestamp/>\n" +
                        "<sp:EncryptSignature/>\n" +
                        "<sp:OnlySignEntireHeadersAndBody/>\n" +
                        "</wsp:Policy>\n" +
                        "</sp:SymmetricBinding>";
        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);
        TimestampSecurityEvent timestampSecurityEvent = new TimestampSecurityEvent();
        policyEnforcer.registerSecurityEvent(timestampSecurityEvent);

        SecurityContextTokenSecurityEvent initiatorTokenSecurityEvent = new SecurityContextTokenSecurityEvent();
        SecureConversationSecurityTokenImpl securityToken =
                new SecureConversationSecurityTokenImpl(
                        null, "1", WSSecurityTokenConstants.KEYIDENTIFIER_SECURITY_TOKEN_DIRECT_REFERENCE);
        securityToken.addTokenUsage(WSSecurityTokenConstants.TOKENUSAGE_MAIN_SIGNATURE);
        initiatorTokenSecurityEvent.setSecurityToken(securityToken);
        policyEnforcer.registerSecurityEvent(initiatorTokenSecurityEvent);

        SecurityContextTokenSecurityEvent recipientTokenSecurityEvent = new SecurityContextTokenSecurityEvent();
        securityToken = new SecureConversationSecurityTokenImpl(
                null, "1", WSSecurityTokenConstants.KEYIDENTIFIER_SECURITY_TOKEN_DIRECT_REFERENCE);
        securityToken.addTokenUsage(WSSecurityTokenConstants.TOKENUSAGE_MAIN_ENCRYPTION);
        recipientTokenSecurityEvent.setSecurityToken(securityToken);
        policyEnforcer.registerSecurityEvent(recipientTokenSecurityEvent);

        List<XMLSecurityConstants.ContentType> protectionOrder = new LinkedList<>();
        protectionOrder.add(XMLSecurityConstants.ContentType.SIGNATURE);
        protectionOrder.add(XMLSecurityConstants.ContentType.ENCRYPTION);
        EncryptedElementSecurityEvent encryptedElementSecurityEvent = new EncryptedElementSecurityEvent(null, true, protectionOrder);
        List<QName> headerPath = new ArrayList<>();
        headerPath.addAll(WSSConstants.WSSE_SECURITY_HEADER_PATH);
        headerPath.add(WSSConstants.TAG_dsig_Signature);
        encryptedElementSecurityEvent.setElementPath(headerPath);
        policyEnforcer.registerSecurityEvent(encryptedElementSecurityEvent);

        encryptedElementSecurityEvent = new EncryptedElementSecurityEvent(null, true, protectionOrder);
        headerPath = new ArrayList<>();
        headerPath.addAll(WSSConstants.WSSE_SECURITY_HEADER_PATH);
        headerPath.add(WSSConstants.TAG_WSSE11_SIG_CONF);
        encryptedElementSecurityEvent.setElementPath(headerPath);
        policyEnforcer.registerSecurityEvent(encryptedElementSecurityEvent);

        OperationSecurityEvent operationSecurityEvent = new OperationSecurityEvent();
        operationSecurityEvent.setOperation(new QName("definitions"));
        policyEnforcer.registerSecurityEvent(operationSecurityEvent);

        SignedPartSecurityEvent signedPartSecurityEvent = new SignedPartSecurityEvent(null, true, protectionOrder);
        QName elementName = new QName("http://www.example.com", "bodyChildElement");
        signedPartSecurityEvent.setXmlSecEvent(XMLSecEventFactory.createXmlSecStartElement(elementName, null, null));
        List<QName> elementPath = new ArrayList<>();
        elementPath.addAll(WSSConstants.SOAP_11_BODY_PATH);
        elementPath.add(elementName);
        signedPartSecurityEvent.setElementPath(elementPath);
        try {
            policyEnforcer.registerSecurityEvent(signedPartSecurityEvent);
            Assert.fail("Exception expected");
        } catch (WSSecurityException e) {
            Assert.assertTrue(e.getCause() instanceof PolicyViolationException);
            Assert.assertEquals(e.getCause().getMessage(),
                    "OnlySignEntireHeadersAndBody not fulfilled, offending element: " +
                            "/{http://schemas.xmlsoap.org/soap/envelope/}Envelope/{http://schemas.xmlsoap.org/soap/envelope/}Body/{http://www.example.com}bodyChildElement");
            Assert.assertEquals(e.getFaultCode(), WSSecurityException.INVALID_SECURITY);
        }
    }
}
