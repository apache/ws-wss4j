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
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

import javax.xml.namespace.QName;

import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.policy.stax.PolicyViolationException;
import org.apache.wss4j.policy.stax.enforcer.PolicyEnforcer;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.impl.securityToken.X509SecurityTokenImpl;
import org.apache.wss4j.stax.securityEvent.OperationSecurityEvent;
import org.apache.wss4j.stax.securityToken.WSSecurityTokenConstants;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.impl.securityToken.AbstractInboundSecurityToken;
import org.apache.xml.security.stax.impl.util.IDGenerator;
import org.apache.xml.security.stax.securityEvent.EncryptedKeyTokenSecurityEvent;
import org.apache.xml.security.stax.securityEvent.SignedElementSecurityEvent;
import org.apache.xml.security.stax.securityEvent.X509TokenSecurityEvent;
import org.apache.xml.security.stax.securityToken.InboundSecurityToken;
import org.apache.xml.security.stax.securityToken.SecurityToken;
import org.apache.xml.security.stax.securityToken.SecurityTokenConstants;
import org.junit.Assert;
import org.junit.Test;

public class TokenProtectionTest extends AbstractPolicyTestBase {

    private static List<WSSecurityTokenConstants.TokenUsage> tokenUsages = new ArrayList<>();

    static {
        tokenUsages.add(WSSecurityTokenConstants.TokenUsage_Signature);
        tokenUsages.add(WSSecurityTokenConstants.TokenUsage_Encryption);
        tokenUsages.add(WSSecurityTokenConstants.TokenUsage_MainSignature);
        tokenUsages.add(WSSecurityTokenConstants.TokenUsage_MainEncryption);
        tokenUsages.add(WSSecurityTokenConstants.TokenUsage_SupportingTokens);
        tokenUsages.add(WSSecurityTokenConstants.TokenUsage_SignedSupportingTokens);
        tokenUsages.add(WSSecurityTokenConstants.TokenUsage_SignedEndorsingSupportingTokens);
        tokenUsages.add(WSSecurityTokenConstants.TokenUsage_SignedEncryptedSupportingTokens);
        tokenUsages.add(WSSecurityTokenConstants.TokenUsage_SignedEndorsingEncryptedSupportingTokens);
        tokenUsages.add(WSSecurityTokenConstants.TokenUsage_EndorsingEncryptedSupportingTokens);
        tokenUsages.add(WSSecurityTokenConstants.TokenUsage_EndorsingSupportingTokens);
        tokenUsages.add(WSSecurityTokenConstants.TokenUsage_EncryptedSupportingTokens);
    }

    @Test
    public void testPolicy() throws Exception {
        String policyString =
                "<sp:AsymmetricBinding xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\" xmlns:sp3=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200802\">\n" +
                        "<wsp:Policy xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">\n" +
                        "   <sp:AlgorithmSuite>\n" +
                        "       <wsp:Policy>\n" +
                        "           <sp:Basic256/>\n" +
                        "       </wsp:Policy>\n" +
                        "   </sp:AlgorithmSuite>\n" +
                        "<sp:ProtectTokens/>\n" +
                        "</wsp:Policy>\n" +
                        "</sp:AsymmetricBinding>";
        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);

        List<XMLSecurityConstants.ContentType> protectionOrder = new LinkedList<>();
        protectionOrder.add(XMLSecurityConstants.ContentType.SIGNATURE);

        List<QName> bstPath = new ArrayList<>();
        bstPath.addAll(WSSConstants.WSSE_SECURITY_HEADER_PATH);
        bstPath.add(WSSConstants.TAG_WSSE_BINARY_SECURITY_TOKEN);

        List<QName> sigPath = new ArrayList<>();
        sigPath.addAll(WSSConstants.WSSE_SECURITY_HEADER_PATH);
        sigPath.add(WSSConstants.TAG_dsig_Signature);

        List<SecurityToken> securityTokens = new LinkedList<>();

        for (int i = 0; i < tokenUsages.size(); i++) {
            WSSecurityTokenConstants.TokenUsage tokenUsage = tokenUsages.get(i);
            X509TokenSecurityEvent x509TokenSecurityEvent = new X509TokenSecurityEvent();
            X509SecurityTokenImpl securityToken = getX509Token(WSSecurityTokenConstants.X509V3Token);
            securityTokens.add(securityToken);

            securityToken.setElementPath(bstPath);
            securityToken.addTokenUsage(tokenUsage);
            x509TokenSecurityEvent.setSecurityToken(securityToken);
            policyEnforcer.registerSecurityEvent(x509TokenSecurityEvent);

            if (tokenUsage.getName().contains("Signature") || tokenUsage.getName().contains("Endorsing")) {
                SignedElementSecurityEvent signedElementSecurityEvent = new SignedElementSecurityEvent(securityToken, true, protectionOrder);
                signedElementSecurityEvent.setElementPath(bstPath);
                policyEnforcer.registerSecurityEvent(signedElementSecurityEvent);
            }

            if (tokenUsage.getName().contains("Endorsing")) {
                SignedElementSecurityEvent signedElementSecurityEvent = new SignedElementSecurityEvent(securityToken, true, protectionOrder);
                signedElementSecurityEvent.setElementPath(sigPath);
                policyEnforcer.registerSecurityEvent(signedElementSecurityEvent);
            }
        }

        SecurityToken mainSignatureToken = null;
        Iterator<SecurityToken> securityTokenIterator = securityTokens.iterator();
        while (securityTokenIterator.hasNext()) {
            SecurityToken securityToken = securityTokenIterator.next();
            if (securityToken.getTokenUsages().contains(WSSecurityTokenConstants.TokenUsage_MainSignature)) {
                mainSignatureToken = securityToken;
                break;
            }
        }

        securityTokenIterator = securityTokens.iterator();
        while (securityTokenIterator.hasNext()) {
            SecurityToken securityToken = securityTokenIterator.next();
            if (securityToken.getTokenUsages().get(0).getName().contains("Signed")) {
                SignedElementSecurityEvent signedElementSecurityEvent =
                        new SignedElementSecurityEvent((InboundSecurityToken)mainSignatureToken, true, protectionOrder);
                signedElementSecurityEvent.setElementPath(bstPath);
                policyEnforcer.registerSecurityEvent(signedElementSecurityEvent);
            }
        }

        OperationSecurityEvent operationSecurityEvent = new OperationSecurityEvent();
        operationSecurityEvent.setOperation(new QName("definitions"));
        policyEnforcer.registerSecurityEvent(operationSecurityEvent);

        policyEnforcer.doFinal();
    }

    @Test
    public void testPolicyNoTokenProtection() throws Exception {
        String policyString =
                "<sp:AsymmetricBinding xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\" xmlns:sp3=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200802\">\n" +
                        "<wsp:Policy xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">\n" +
                        "   <sp:AlgorithmSuite>\n" +
                        "       <wsp:Policy>\n" +
                        "           <sp:Basic256/>\n" +
                        "       </wsp:Policy>\n" +
                        "   </sp:AlgorithmSuite>\n" +
                        "</wsp:Policy>\n" +
                        "</sp:AsymmetricBinding>";
        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);

        List<XMLSecurityConstants.ContentType> protectionOrder = new LinkedList<>();
        protectionOrder.add(XMLSecurityConstants.ContentType.SIGNATURE);

        List<QName> bstPath = new ArrayList<>();
        bstPath.addAll(WSSConstants.WSSE_SECURITY_HEADER_PATH);
        bstPath.add(WSSConstants.TAG_WSSE_BINARY_SECURITY_TOKEN);

        List<QName> sigPath = new ArrayList<>();
        sigPath.addAll(WSSConstants.WSSE_SECURITY_HEADER_PATH);
        sigPath.add(WSSConstants.TAG_dsig_Signature);

        List<SecurityToken> securityTokens = new LinkedList<>();

        for (int i = 0; i < tokenUsages.size(); i++) {
            WSSecurityTokenConstants.TokenUsage tokenUsage = tokenUsages.get(i);
            X509TokenSecurityEvent x509TokenSecurityEvent = new X509TokenSecurityEvent();
            X509SecurityTokenImpl securityToken = getX509Token(WSSecurityTokenConstants.X509V3Token);
            securityTokens.add(securityToken);

            securityToken.setElementPath(bstPath);
            securityToken.addTokenUsage(tokenUsage);
            x509TokenSecurityEvent.setSecurityToken(securityToken);
            policyEnforcer.registerSecurityEvent(x509TokenSecurityEvent);

            if (tokenUsage.getName().contains("Endorsing")) {
                SignedElementSecurityEvent signedElementSecurityEvent = new SignedElementSecurityEvent(securityToken, true, protectionOrder);
                signedElementSecurityEvent.setElementPath(sigPath);
                policyEnforcer.registerSecurityEvent(signedElementSecurityEvent);
            }
        }

        SecurityToken mainSignatureToken = null;
        Iterator<SecurityToken> securityTokenIterator = securityTokens.iterator();
        while (securityTokenIterator.hasNext()) {
            SecurityToken securityToken = securityTokenIterator.next();
            if (securityToken.getTokenUsages().contains(WSSecurityTokenConstants.TokenUsage_MainSignature)) {
                mainSignatureToken = securityToken;
                break;
            }
        }

        securityTokenIterator = securityTokens.iterator();
        while (securityTokenIterator.hasNext()) {
            SecurityToken securityToken = securityTokenIterator.next();
            if (securityToken.getTokenUsages().get(0).getName().contains("Signed")) {
                SignedElementSecurityEvent signedElementSecurityEvent =
                        new SignedElementSecurityEvent((InboundSecurityToken)mainSignatureToken, true, protectionOrder);
                signedElementSecurityEvent.setElementPath(bstPath);
                policyEnforcer.registerSecurityEvent(signedElementSecurityEvent);
            }
        }

        OperationSecurityEvent operationSecurityEvent = new OperationSecurityEvent();
        operationSecurityEvent.setOperation(new QName("definitions"));
        try {
            policyEnforcer.registerSecurityEvent(operationSecurityEvent);
        } catch (WSSecurityException e) {
            Assert.assertTrue(e.getCause() instanceof PolicyViolationException);
            Assert.assertEquals(e.getCause().getMessage(),
                    "Token /{http://schemas.xmlsoap.org/soap/envelope/}Envelope/{http://schemas.xmlsoap.org/soap/envelope/}Header/{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd}Security/{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd}BinarySecurityToken must not be signed by its signature.");
            Assert.assertEquals(e.getFaultCode(), WSSecurityException.INVALID_SECURITY);
        }
    }

    @Test
    public void testPolicyElementNotSigned() throws Exception {
        String policyString =
                "<sp:AsymmetricBinding xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\" xmlns:sp3=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200802\">\n" +
                        "<wsp:Policy xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">\n" +
                        "   <sp:AlgorithmSuite>\n" +
                        "       <wsp:Policy>\n" +
                        "           <sp:Basic256/>\n" +
                        "       </wsp:Policy>\n" +
                        "   </sp:AlgorithmSuite>\n" +
                        "<sp:ProtectTokens/>\n" +
                        "</wsp:Policy>\n" +
                        "</sp:AsymmetricBinding>";
        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);

        X509TokenSecurityEvent x509TokenSecurityEvent = new X509TokenSecurityEvent();
        X509SecurityTokenImpl securityToken = getX509Token(WSSecurityTokenConstants.X509V3Token);
        List<QName> path = new ArrayList<>();
        path.addAll(WSSConstants.WSSE_SECURITY_HEADER_PATH);
        path.add(WSSConstants.TAG_WSSE_BINARY_SECURITY_TOKEN);
        securityToken.setElementPath(path);
        securityToken.addTokenUsage(WSSecurityTokenConstants.TokenUsage_MainSignature);
        x509TokenSecurityEvent.setSecurityToken(securityToken);
        policyEnforcer.registerSecurityEvent(x509TokenSecurityEvent);

        List<XMLSecurityConstants.ContentType> protectionOrder = new LinkedList<>();
        protectionOrder.add(XMLSecurityConstants.ContentType.SIGNATURE);

        SignedElementSecurityEvent signedElementSecurityEvent = new SignedElementSecurityEvent(securityToken, false, protectionOrder);
        signedElementSecurityEvent.setElementPath(path);
        policyEnforcer.registerSecurityEvent(signedElementSecurityEvent);

        OperationSecurityEvent operationSecurityEvent = new OperationSecurityEvent();
        operationSecurityEvent.setOperation(new QName("definitions"));

        try {
            policyEnforcer.registerSecurityEvent(operationSecurityEvent);
            Assert.fail("Exception expected");
        } catch (WSSecurityException e) {
            Assert.assertTrue(e.getCause() instanceof PolicyViolationException);
            Assert.assertEquals(e.getCause().getMessage(),
                    "Token /{http://schemas.xmlsoap.org/soap/envelope/}Envelope/{http://schemas.xmlsoap.org/soap/envelope/}Header/{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd}Security/{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd}BinarySecurityToken must be signed by its signature.");
            Assert.assertEquals(e.getFaultCode(), WSSecurityException.INVALID_SECURITY);
        }
    }

    @Test
    public void testPolicyElementSignedByOtherSignature() throws Exception {
        String policyString =
                "<sp:AsymmetricBinding xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\" xmlns:sp3=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200802\">\n" +
                        "<wsp:Policy xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">\n" +
                        "   <sp:AlgorithmSuite>\n" +
                        "       <wsp:Policy>\n" +
                        "           <sp:Basic256/>\n" +
                        "       </wsp:Policy>\n" +
                        "   </sp:AlgorithmSuite>\n" +
                        "<sp:ProtectTokens/>\n" +
                        "</wsp:Policy>\n" +
                        "</sp:AsymmetricBinding>";
        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);

        X509TokenSecurityEvent x509TokenSecurityEvent = new X509TokenSecurityEvent();
        X509SecurityTokenImpl securityToken = getX509Token(WSSecurityTokenConstants.X509V3Token);
        List<QName> path = new ArrayList<>();
        path.addAll(WSSConstants.WSSE_SECURITY_HEADER_PATH);
        path.add(WSSConstants.TAG_WSSE_BINARY_SECURITY_TOKEN);
        securityToken.setElementPath(path);
        securityToken.addTokenUsage(WSSecurityTokenConstants.TokenUsage_MainSignature);
        x509TokenSecurityEvent.setSecurityToken(securityToken);
        policyEnforcer.registerSecurityEvent(x509TokenSecurityEvent);

        List<XMLSecurityConstants.ContentType> protectionOrder = new LinkedList<>();
        protectionOrder.add(XMLSecurityConstants.ContentType.SIGNATURE);

        SignedElementSecurityEvent signedElementSecurityEvent = new SignedElementSecurityEvent(getX509Token(WSSecurityTokenConstants.X509V3Token), false, protectionOrder);
        signedElementSecurityEvent.setElementPath(path);
        policyEnforcer.registerSecurityEvent(signedElementSecurityEvent);

        OperationSecurityEvent operationSecurityEvent = new OperationSecurityEvent();
        operationSecurityEvent.setOperation(new QName("definitions"));

        try {
            policyEnforcer.registerSecurityEvent(operationSecurityEvent);
            Assert.fail("Exception expected");
        } catch (WSSecurityException e) {
            Assert.assertTrue(e.getCause() instanceof PolicyViolationException);
            Assert.assertEquals(e.getCause().getMessage(),
                    "Token /{http://schemas.xmlsoap.org/soap/envelope/}Envelope/{http://schemas.xmlsoap.org/soap/envelope/}Header/{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd}Security/{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd}BinarySecurityToken must be signed by its signature.");
            Assert.assertEquals(e.getFaultCode(), WSSecurityException.INVALID_SECURITY);
        }
    }

    @Test
    public void testPolicyElementSignedByOtherSignatureReverseSecurityEventOrder() throws Exception {
        String policyString =
                "<sp:AsymmetricBinding xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\" xmlns:sp3=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200802\">\n" +
                        "<wsp:Policy xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">\n" +
                        "   <sp:AlgorithmSuite>\n" +
                        "       <wsp:Policy>\n" +
                        "           <sp:Basic256/>\n" +
                        "       </wsp:Policy>\n" +
                        "   </sp:AlgorithmSuite>\n" +
                        "<sp:ProtectTokens/>\n" +
                        "</wsp:Policy>\n" +
                        "</sp:AsymmetricBinding>";
        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);

        X509TokenSecurityEvent x509TokenSecurityEvent = new X509TokenSecurityEvent();
        X509SecurityTokenImpl securityToken = getX509Token(WSSecurityTokenConstants.X509V3Token);
        List<QName> path = new ArrayList<>();
        path.addAll(WSSConstants.WSSE_SECURITY_HEADER_PATH);
        path.add(WSSConstants.TAG_WSSE_BINARY_SECURITY_TOKEN);
        securityToken.setElementPath(path);
        securityToken.addTokenUsage(WSSecurityTokenConstants.TokenUsage_MainSignature);
        x509TokenSecurityEvent.setSecurityToken(securityToken);

        List<XMLSecurityConstants.ContentType> protectionOrder = new LinkedList<>();
        protectionOrder.add(XMLSecurityConstants.ContentType.SIGNATURE);

        SignedElementSecurityEvent signedElementSecurityEvent = new SignedElementSecurityEvent(getX509Token(WSSecurityTokenConstants.X509V3Token), false, protectionOrder);
        signedElementSecurityEvent.setElementPath(path);
        policyEnforcer.registerSecurityEvent(signedElementSecurityEvent);

        policyEnforcer.registerSecurityEvent(x509TokenSecurityEvent);

        OperationSecurityEvent operationSecurityEvent = new OperationSecurityEvent();
        operationSecurityEvent.setOperation(new QName("definitions"));

        try {
            policyEnforcer.registerSecurityEvent(operationSecurityEvent);
            Assert.fail("Exception expected");
        } catch (WSSecurityException e) {
            Assert.assertTrue(e.getCause() instanceof PolicyViolationException);
            Assert.assertEquals(e.getCause().getMessage(),
                    "Token /{http://schemas.xmlsoap.org/soap/envelope/}Envelope/{http://schemas.xmlsoap.org/soap/envelope/}Header/{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd}Security/{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd}BinarySecurityToken must be signed by its signature.");
            Assert.assertEquals(e.getFaultCode(), WSSecurityException.INVALID_SECURITY);
        }
    }

    @Test
    public void testPolicyEndorsingTokenNotSigningMainSignatureToken() throws Exception {
        String policyString =
                "<sp:AsymmetricBinding xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\" xmlns:sp3=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200802\">\n" +
                        "<wsp:Policy xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">\n" +
                        "   <sp:AlgorithmSuite>\n" +
                        "       <wsp:Policy>\n" +
                        "           <sp:Basic256/>\n" +
                        "       </wsp:Policy>\n" +
                        "   </sp:AlgorithmSuite>\n" +
                        "<sp:ProtectTokens/>\n" +
                        "</wsp:Policy>\n" +
                        "</sp:AsymmetricBinding>";
        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);

        List<XMLSecurityConstants.ContentType> protectionOrder = new LinkedList<>();
        protectionOrder.add(XMLSecurityConstants.ContentType.SIGNATURE);

        List<QName> bstPath = new ArrayList<>();
        bstPath.addAll(WSSConstants.WSSE_SECURITY_HEADER_PATH);
        bstPath.add(WSSConstants.TAG_WSSE_BINARY_SECURITY_TOKEN);

        List<SecurityToken> securityTokens = new LinkedList<>();

        for (int i = 0; i < tokenUsages.size(); i++) {
            WSSecurityTokenConstants.TokenUsage tokenUsage = tokenUsages.get(i);
            X509TokenSecurityEvent x509TokenSecurityEvent = new X509TokenSecurityEvent();
            X509SecurityTokenImpl securityToken = getX509Token(WSSecurityTokenConstants.X509V3Token);

            securityTokens.add(securityToken);

            securityToken.setElementPath(bstPath);
            securityToken.addTokenUsage(tokenUsage);
            x509TokenSecurityEvent.setSecurityToken(securityToken);
            policyEnforcer.registerSecurityEvent(x509TokenSecurityEvent);

            if (tokenUsage.getName().contains("Signature") || tokenUsage.getName().contains("Endorsing")) {
                SignedElementSecurityEvent signedElementSecurityEvent = new SignedElementSecurityEvent(securityToken, true, protectionOrder);
                signedElementSecurityEvent.setElementPath(bstPath);
                policyEnforcer.registerSecurityEvent(signedElementSecurityEvent);
            }
        }

        SecurityToken mainSignatureToken = null;
        Iterator<SecurityToken> securityTokenIterator = securityTokens.iterator();
        while (securityTokenIterator.hasNext()) {
            SecurityToken securityToken = securityTokenIterator.next();
            if (securityToken.getTokenUsages().contains(WSSecurityTokenConstants.TokenUsage_MainSignature)) {
                mainSignatureToken = securityToken;
                break;
            }
        }

        securityTokenIterator = securityTokens.iterator();
        while (securityTokenIterator.hasNext()) {
            SecurityToken securityToken = securityTokenIterator.next();
            if (securityToken.getTokenUsages().get(0).getName().contains("Signed")) {
                SignedElementSecurityEvent signedElementSecurityEvent =
                        new SignedElementSecurityEvent((InboundSecurityToken)mainSignatureToken, true, protectionOrder);
                signedElementSecurityEvent.setElementPath(bstPath);
                policyEnforcer.registerSecurityEvent(signedElementSecurityEvent);
            }
        }

        OperationSecurityEvent operationSecurityEvent = new OperationSecurityEvent();
        operationSecurityEvent.setOperation(new QName("definitions"));
        try {
            policyEnforcer.registerSecurityEvent(operationSecurityEvent);
        } catch (WSSecurityException e) {
            Assert.assertTrue(e.getCause() instanceof PolicyViolationException);
            Assert.assertEquals(e.getCause().getMessage(),
                    "Token /{http://schemas.xmlsoap.org/soap/envelope/}Envelope/{http://schemas.xmlsoap.org/soap/envelope/}Header/{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd}Security/{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd}BinarySecurityToken must sign the main signature.");
            Assert.assertEquals(e.getFaultCode(), WSSecurityException.INVALID_SECURITY);
        }
    }

    @Test
    public void testPolicyMainSignatureNotSigningEndorsingSignatureTokens() throws Exception {
        String policyString =
                "<sp:AsymmetricBinding xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\" xmlns:sp3=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200802\">\n" +
                        "<wsp:Policy xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">\n" +
                        "   <sp:AlgorithmSuite>\n" +
                        "       <wsp:Policy>\n" +
                        "           <sp:Basic256/>\n" +
                        "       </wsp:Policy>\n" +
                        "   </sp:AlgorithmSuite>\n" +
                        "<sp:ProtectTokens/>\n" +
                        "</wsp:Policy>\n" +
                        "</sp:AsymmetricBinding>";
        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);

        List<XMLSecurityConstants.ContentType> protectionOrder = new LinkedList<>();
        protectionOrder.add(XMLSecurityConstants.ContentType.SIGNATURE);

        List<QName> bstPath = new ArrayList<>();
        bstPath.addAll(WSSConstants.WSSE_SECURITY_HEADER_PATH);
        bstPath.add(WSSConstants.TAG_WSSE_BINARY_SECURITY_TOKEN);

        List<QName> sigPath = new ArrayList<>();
        sigPath.addAll(WSSConstants.WSSE_SECURITY_HEADER_PATH);
        sigPath.add(WSSConstants.TAG_dsig_Signature);

        for (int i = 0; i < tokenUsages.size(); i++) {
            WSSecurityTokenConstants.TokenUsage tokenUsage = tokenUsages.get(i);
            X509TokenSecurityEvent x509TokenSecurityEvent = new X509TokenSecurityEvent();
            X509SecurityTokenImpl securityToken = getX509Token(WSSecurityTokenConstants.X509V3Token);

            securityToken.setElementPath(bstPath);
            securityToken.addTokenUsage(tokenUsage);
            x509TokenSecurityEvent.setSecurityToken(securityToken);
            policyEnforcer.registerSecurityEvent(x509TokenSecurityEvent);

            if (tokenUsage.getName().contains("Signature") || tokenUsage.getName().contains("Endorsing")) {
                SignedElementSecurityEvent signedElementSecurityEvent = new SignedElementSecurityEvent(securityToken, true, protectionOrder);
                signedElementSecurityEvent.setElementPath(bstPath);
                policyEnforcer.registerSecurityEvent(signedElementSecurityEvent);
            }

            if (tokenUsage.getName().contains("Endorsing")) {
                SignedElementSecurityEvent signedElementSecurityEvent = new SignedElementSecurityEvent(securityToken, true, protectionOrder);
                signedElementSecurityEvent.setElementPath(sigPath);
                policyEnforcer.registerSecurityEvent(signedElementSecurityEvent);
            }
        }

        OperationSecurityEvent operationSecurityEvent = new OperationSecurityEvent();
        operationSecurityEvent.setOperation(new QName("definitions"));

        try {
            policyEnforcer.registerSecurityEvent(operationSecurityEvent);
        } catch (WSSecurityException e) {
            Assert.assertTrue(e.getCause() instanceof PolicyViolationException);
            Assert.assertEquals(e.getCause().getMessage(),
                    "Main signature must sign the Signed*Supporting-Tokens.");
            Assert.assertEquals(e.getFaultCode(), WSSecurityException.INVALID_SECURITY);
        }
    }

    @Test
    public void testPolicySymmetricBindingProtectSignatureToken() throws Exception {
        String policyString =
                "<sp:SymmetricBinding xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\" xmlns:sp3=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200802\">\n" +
                        "<wsp:Policy xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">\n" +
                        "   <sp:AlgorithmSuite>\n" +
                        "       <wsp:Policy>\n" +
                        "           <sp:Basic256/>\n" +
                        "       </wsp:Policy>\n" +
                        "   </sp:AlgorithmSuite>\n" +
                        "<sp:ProtectTokens/>\n" +
                        "</wsp:Policy>\n" +
                        "</sp:SymmetricBinding>";
        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);

        List<XMLSecurityConstants.ContentType> protectionOrder = new LinkedList<>();
        protectionOrder.add(XMLSecurityConstants.ContentType.SIGNATURE);

        List<QName> bstPath = new ArrayList<>();
        bstPath.addAll(WSSConstants.WSSE_SECURITY_HEADER_PATH);
        bstPath.add(WSSConstants.TAG_WSSE_BINARY_SECURITY_TOKEN);

        List<QName> ekPath = new ArrayList<>();
        ekPath.addAll(WSSConstants.WSSE_SECURITY_HEADER_PATH);
        ekPath.add(WSSConstants.TAG_xenc_EncryptedKey);

        List<QName> sigPath = new ArrayList<>();
        sigPath.addAll(WSSConstants.WSSE_SECURITY_HEADER_PATH);
        sigPath.add(WSSConstants.TAG_dsig_Signature);

        X509SecurityTokenImpl x509SecurityToken = getX509Token(WSSecurityTokenConstants.X509V3Token);
        x509SecurityToken.addTokenUsage(WSSecurityTokenConstants.TokenUsage_MainSignature);
        x509SecurityToken.setElementPath(bstPath);

        AbstractInboundSecurityToken ekSecurityToken = new AbstractInboundSecurityToken(
                null, IDGenerator.generateID(null),
                SecurityTokenConstants.KeyIdentifier_EncryptedKey, true) {
            @Override
            public SecurityTokenConstants.TokenType getTokenType() {
                return SecurityTokenConstants.EncryptedKeyToken;
            }
        };
        ekSecurityToken.addTokenUsage(WSSecurityTokenConstants.TokenUsage_Signature);
        ekSecurityToken.setKeyWrappingToken(x509SecurityToken);
        ekSecurityToken.setElementPath(ekPath);

        x509SecurityToken.addWrappedToken(ekSecurityToken);

        X509TokenSecurityEvent x509TokenSecurityEvent = new X509TokenSecurityEvent();
        x509TokenSecurityEvent.setSecurityToken(x509SecurityToken);
        policyEnforcer.registerSecurityEvent(x509TokenSecurityEvent);

        EncryptedKeyTokenSecurityEvent encryptedKeyTokenSecurityEvent = new EncryptedKeyTokenSecurityEvent();
        encryptedKeyTokenSecurityEvent.setSecurityToken(ekSecurityToken);
        policyEnforcer.registerSecurityEvent(encryptedKeyTokenSecurityEvent);

        SignedElementSecurityEvent signedElementSecurityEvent = new SignedElementSecurityEvent(ekSecurityToken, true, protectionOrder);
        signedElementSecurityEvent.setElementPath(ekPath);
        policyEnforcer.registerSecurityEvent(signedElementSecurityEvent);

        OperationSecurityEvent operationSecurityEvent = new OperationSecurityEvent();
        operationSecurityEvent.setOperation(new QName("definitions"));

        policyEnforcer.registerSecurityEvent(operationSecurityEvent);
        policyEnforcer.doFinal();
    }

    @Test
    public void testPolicySymmetricBindingProtectRootToken() throws Exception {
        String policyString =
                "<sp:SymmetricBinding xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\" xmlns:sp3=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200802\">\n" +
                        "<wsp:Policy xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">\n" +
                        "   <sp:AlgorithmSuite>\n" +
                        "       <wsp:Policy>\n" +
                        "           <sp:Basic256/>\n" +
                        "       </wsp:Policy>\n" +
                        "   </sp:AlgorithmSuite>\n" +
                        "<sp:ProtectTokens/>\n" +
                        "</wsp:Policy>\n" +
                        "</sp:SymmetricBinding>";
        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);

        List<XMLSecurityConstants.ContentType> protectionOrder = new LinkedList<>();
        protectionOrder.add(XMLSecurityConstants.ContentType.SIGNATURE);

        List<QName> bstPath = new ArrayList<>();
        bstPath.addAll(WSSConstants.WSSE_SECURITY_HEADER_PATH);
        bstPath.add(WSSConstants.TAG_WSSE_BINARY_SECURITY_TOKEN);

        List<QName> ekPath = new ArrayList<>();
        ekPath.addAll(WSSConstants.WSSE_SECURITY_HEADER_PATH);
        ekPath.add(WSSConstants.TAG_xenc_EncryptedKey);

        List<QName> sigPath = new ArrayList<>();
        sigPath.addAll(WSSConstants.WSSE_SECURITY_HEADER_PATH);
        sigPath.add(WSSConstants.TAG_dsig_Signature);

        X509SecurityTokenImpl x509SecurityToken = getX509Token(WSSecurityTokenConstants.X509V3Token);
        x509SecurityToken.addTokenUsage(WSSecurityTokenConstants.TokenUsage_MainSignature);
        x509SecurityToken.setElementPath(bstPath);

        AbstractInboundSecurityToken ekSecurityToken = new AbstractInboundSecurityToken(
                null, IDGenerator.generateID(null),
                SecurityTokenConstants.KeyIdentifier_EncryptedKey, true) {
            @Override
            public SecurityTokenConstants.TokenType getTokenType() {
                return SecurityTokenConstants.EncryptedKeyToken;
            }
        };
        ekSecurityToken.addTokenUsage(WSSecurityTokenConstants.TokenUsage_Signature);
        ekSecurityToken.setKeyWrappingToken(x509SecurityToken);
        ekSecurityToken.setElementPath(ekPath);

        x509SecurityToken.addWrappedToken(ekSecurityToken);

        X509TokenSecurityEvent x509TokenSecurityEvent = new X509TokenSecurityEvent();
        x509TokenSecurityEvent.setSecurityToken(x509SecurityToken);
        policyEnforcer.registerSecurityEvent(x509TokenSecurityEvent);

        EncryptedKeyTokenSecurityEvent encryptedKeyTokenSecurityEvent = new EncryptedKeyTokenSecurityEvent();
        encryptedKeyTokenSecurityEvent.setSecurityToken(ekSecurityToken);
        policyEnforcer.registerSecurityEvent(encryptedKeyTokenSecurityEvent);

        SignedElementSecurityEvent signedElementSecurityEvent = new SignedElementSecurityEvent(x509SecurityToken, true, protectionOrder);
        signedElementSecurityEvent.setElementPath(bstPath);
        policyEnforcer.registerSecurityEvent(signedElementSecurityEvent);

        OperationSecurityEvent operationSecurityEvent = new OperationSecurityEvent();
        operationSecurityEvent.setOperation(new QName("definitions"));

        try {
            policyEnforcer.registerSecurityEvent(operationSecurityEvent);
        } catch (WSSecurityException e) {
            Assert.assertTrue(e.getCause() instanceof PolicyViolationException);
            Assert.assertEquals(e.getCause().getMessage(),
                    "Token /{http://schemas.xmlsoap.org/soap/envelope/}Envelope/{http://schemas.xmlsoap.org/soap/envelope/}Header/{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd}Security/{http://www.w3.org/2001/04/xmlenc#}EncryptedKey must be signed by its signature.");
            Assert.assertEquals(e.getFaultCode(), WSSecurityException.INVALID_SECURITY);
        }
    }

    @Test
    public void testPolicySymmetricBindingProtectAllToken() throws Exception {
        String policyString =
                "<sp:SymmetricBinding xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\" xmlns:sp3=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200802\">\n" +
                        "<wsp:Policy xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">\n" +
                        "   <sp:AlgorithmSuite>\n" +
                        "       <wsp:Policy>\n" +
                        "           <sp:Basic256/>\n" +
                        "       </wsp:Policy>\n" +
                        "   </sp:AlgorithmSuite>\n" +
                        "<sp:ProtectTokens/>\n" +
                        "</wsp:Policy>\n" +
                        "</sp:SymmetricBinding>";
        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);

        List<XMLSecurityConstants.ContentType> protectionOrder = new LinkedList<>();
        protectionOrder.add(XMLSecurityConstants.ContentType.SIGNATURE);

        List<QName> bstPath = new ArrayList<>();
        bstPath.addAll(WSSConstants.WSSE_SECURITY_HEADER_PATH);
        bstPath.add(WSSConstants.TAG_WSSE_BINARY_SECURITY_TOKEN);

        List<QName> ekPath = new ArrayList<>();
        ekPath.addAll(WSSConstants.WSSE_SECURITY_HEADER_PATH);
        ekPath.add(WSSConstants.TAG_xenc_EncryptedKey);

        List<QName> sigPath = new ArrayList<>();
        sigPath.addAll(WSSConstants.WSSE_SECURITY_HEADER_PATH);
        sigPath.add(WSSConstants.TAG_dsig_Signature);

        X509SecurityTokenImpl x509SecurityToken = getX509Token(WSSecurityTokenConstants.X509V3Token);
        x509SecurityToken.addTokenUsage(WSSecurityTokenConstants.TokenUsage_MainSignature);
        x509SecurityToken.setElementPath(bstPath);

        AbstractInboundSecurityToken ekSecurityToken = new AbstractInboundSecurityToken(
                null, IDGenerator.generateID(null),
                SecurityTokenConstants.KeyIdentifier_EncryptedKey, true) {
            @Override
            public SecurityTokenConstants.TokenType getTokenType() {
                return SecurityTokenConstants.EncryptedKeyToken;
            }
        };
        ekSecurityToken.addTokenUsage(WSSecurityTokenConstants.TokenUsage_Signature);
        ekSecurityToken.setKeyWrappingToken(x509SecurityToken);
        ekSecurityToken.setElementPath(ekPath);

        x509SecurityToken.addWrappedToken(ekSecurityToken);

        X509TokenSecurityEvent x509TokenSecurityEvent = new X509TokenSecurityEvent();
        x509TokenSecurityEvent.setSecurityToken(x509SecurityToken);
        policyEnforcer.registerSecurityEvent(x509TokenSecurityEvent);

        EncryptedKeyTokenSecurityEvent encryptedKeyTokenSecurityEvent = new EncryptedKeyTokenSecurityEvent();
        encryptedKeyTokenSecurityEvent.setSecurityToken(ekSecurityToken);
        policyEnforcer.registerSecurityEvent(encryptedKeyTokenSecurityEvent);

        SignedElementSecurityEvent signedElementSecurityEvent = new SignedElementSecurityEvent(x509SecurityToken, true, protectionOrder);
        signedElementSecurityEvent.setElementPath(bstPath);
        policyEnforcer.registerSecurityEvent(signedElementSecurityEvent);

        signedElementSecurityEvent = new SignedElementSecurityEvent(ekSecurityToken, true, protectionOrder);
        signedElementSecurityEvent.setElementPath(ekPath);
        policyEnforcer.registerSecurityEvent(signedElementSecurityEvent);

        OperationSecurityEvent operationSecurityEvent = new OperationSecurityEvent();
        operationSecurityEvent.setOperation(new QName("definitions"));

        policyEnforcer.registerSecurityEvent(operationSecurityEvent);
        policyEnforcer.doFinal();
    }
}
