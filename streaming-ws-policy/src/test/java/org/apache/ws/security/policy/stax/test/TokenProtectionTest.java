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

import org.apache.ws.security.policy.stax.PolicyEnforcer;
import org.apache.ws.security.policy.stax.PolicyViolationException;
import org.swssf.wss.ext.WSSConstants;
import org.swssf.wss.ext.WSSecurityException;
import org.swssf.wss.impl.securityToken.X509SecurityToken;
import org.swssf.wss.securityEvent.OperationSecurityEvent;
import org.apache.xml.security.stax.ext.SecurityToken;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.securityEvent.SignedElementSecurityEvent;
import org.apache.xml.security.stax.securityEvent.X509TokenSecurityEvent;
import org.testng.Assert;
import org.testng.annotations.Test;

import javax.xml.namespace.QName;
import java.util.*;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class TokenProtectionTest extends AbstractPolicyTestBase {

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

        List<XMLSecurityConstants.ContentType> protectionOrder = new LinkedList<XMLSecurityConstants.ContentType>();
        protectionOrder.add(XMLSecurityConstants.ContentType.SIGNATURE);

        List<QName> bstPath = new ArrayList<QName>();
        bstPath.addAll(WSSConstants.WSSE_SECURITY_HEADER_PATH);
        bstPath.add(WSSConstants.TAG_wsse_BinarySecurityToken);

        List<QName> sigPath = new ArrayList<QName>();
        sigPath.addAll(WSSConstants.WSSE_SECURITY_HEADER_PATH);
        sigPath.add(WSSConstants.TAG_dsig_Signature);

        List<SecurityToken> securityTokens = new LinkedList<SecurityToken>();

        for (SecurityToken.TokenUsage tokenUsage : EnumSet.allOf(SecurityToken.TokenUsage.class)) {
            X509TokenSecurityEvent x509TokenSecurityEvent = new X509TokenSecurityEvent();
            X509SecurityToken securityToken = getX509Token(WSSConstants.X509V3Token);
            securityTokens.add(securityToken);

            securityToken.setElementPath(bstPath);
            securityToken.addTokenUsage(tokenUsage);
            x509TokenSecurityEvent.setSecurityToken(securityToken);
            policyEnforcer.registerSecurityEvent(x509TokenSecurityEvent);

            if (tokenUsage.name().contains("Signature") || tokenUsage.name().contains("Endorsing")) {
                SignedElementSecurityEvent signedElementSecurityEvent = new SignedElementSecurityEvent(securityToken, true, protectionOrder);
                signedElementSecurityEvent.setElementPath(bstPath);
                policyEnforcer.registerSecurityEvent(signedElementSecurityEvent);
            }

            if (tokenUsage.name().contains("Endorsing")) {
                SignedElementSecurityEvent signedElementSecurityEvent = new SignedElementSecurityEvent(securityToken, true, protectionOrder);
                signedElementSecurityEvent.setElementPath(sigPath);
                policyEnforcer.registerSecurityEvent(signedElementSecurityEvent);
            }
        }

        SecurityToken mainSignatureToken = null;
        Iterator<SecurityToken> securityTokenIterator = securityTokens.iterator();
        while (securityTokenIterator.hasNext()) {
            SecurityToken securityToken = securityTokenIterator.next();
            if (securityToken.getTokenUsages().contains(SecurityToken.TokenUsage.MainSignature)) {
                mainSignatureToken = securityToken;
                break;
            }
        }

        securityTokenIterator = securityTokens.iterator();
        while (securityTokenIterator.hasNext()) {
            SecurityToken securityToken = securityTokenIterator.next();
            if (securityToken.getTokenUsages().get(0).name().contains("Signed")) {
                SignedElementSecurityEvent signedElementSecurityEvent = new SignedElementSecurityEvent(mainSignatureToken, true, protectionOrder);
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

        List<XMLSecurityConstants.ContentType> protectionOrder = new LinkedList<XMLSecurityConstants.ContentType>();
        protectionOrder.add(XMLSecurityConstants.ContentType.SIGNATURE);

        List<QName> bstPath = new ArrayList<QName>();
        bstPath.addAll(WSSConstants.WSSE_SECURITY_HEADER_PATH);
        bstPath.add(WSSConstants.TAG_wsse_BinarySecurityToken);

        List<QName> sigPath = new ArrayList<QName>();
        sigPath.addAll(WSSConstants.WSSE_SECURITY_HEADER_PATH);
        sigPath.add(WSSConstants.TAG_dsig_Signature);

        List<SecurityToken> securityTokens = new LinkedList<SecurityToken>();

        for (SecurityToken.TokenUsage tokenUsage : EnumSet.allOf(SecurityToken.TokenUsage.class)) {
            X509TokenSecurityEvent x509TokenSecurityEvent = new X509TokenSecurityEvent();
            X509SecurityToken securityToken = getX509Token(WSSConstants.X509V3Token);
            securityTokens.add(securityToken);

            securityToken.setElementPath(bstPath);
            securityToken.addTokenUsage(tokenUsage);
            x509TokenSecurityEvent.setSecurityToken(securityToken);
            policyEnforcer.registerSecurityEvent(x509TokenSecurityEvent);

            if (tokenUsage.name().contains("Endorsing")) {
                SignedElementSecurityEvent signedElementSecurityEvent = new SignedElementSecurityEvent(securityToken, true, protectionOrder);
                signedElementSecurityEvent.setElementPath(sigPath);
                policyEnforcer.registerSecurityEvent(signedElementSecurityEvent);
            }
        }

        SecurityToken mainSignatureToken = null;
        Iterator<SecurityToken> securityTokenIterator = securityTokens.iterator();
        while (securityTokenIterator.hasNext()) {
            SecurityToken securityToken = securityTokenIterator.next();
            if (securityToken.getTokenUsages().contains(SecurityToken.TokenUsage.MainSignature)) {
                mainSignatureToken = securityToken;
                break;
            }
        }

        securityTokenIterator = securityTokens.iterator();
        while (securityTokenIterator.hasNext()) {
            SecurityToken securityToken = securityTokenIterator.next();
            if (securityToken.getTokenUsages().get(0).name().contains("Signed")) {
                SignedElementSecurityEvent signedElementSecurityEvent = new SignedElementSecurityEvent(mainSignatureToken, true, protectionOrder);
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
            Assert.assertEquals(e.getCause().getMessage(), "\n" +
                    "Token /{http://schemas.xmlsoap.org/soap/envelope/}Envelope/{http://schemas.xmlsoap.org/soap/envelope/}Header/{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd}Security/{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd}BinarySecurityToken must not be signed by its signature.");
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
        X509SecurityToken securityToken = getX509Token(WSSConstants.X509V3Token);
        List<QName> path = new ArrayList<QName>();
        path.addAll(WSSConstants.WSSE_SECURITY_HEADER_PATH);
        path.add(WSSConstants.TAG_wsse_BinarySecurityToken);
        securityToken.setElementPath(path);
        securityToken.addTokenUsage(SecurityToken.TokenUsage.MainSignature);
        x509TokenSecurityEvent.setSecurityToken(securityToken);
        policyEnforcer.registerSecurityEvent(x509TokenSecurityEvent);

        List<XMLSecurityConstants.ContentType> protectionOrder = new LinkedList<XMLSecurityConstants.ContentType>();
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
            Assert.assertEquals(e.getCause().getMessage(), "\n" +
                    "Token /{http://schemas.xmlsoap.org/soap/envelope/}Envelope/{http://schemas.xmlsoap.org/soap/envelope/}Header/{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd}Security/{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd}BinarySecurityToken must be signed by its signature.");
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
        X509SecurityToken securityToken = getX509Token(WSSConstants.X509V3Token);
        List<QName> path = new ArrayList<QName>();
        path.addAll(WSSConstants.WSSE_SECURITY_HEADER_PATH);
        path.add(WSSConstants.TAG_wsse_BinarySecurityToken);
        securityToken.setElementPath(path);
        securityToken.addTokenUsage(SecurityToken.TokenUsage.MainSignature);
        x509TokenSecurityEvent.setSecurityToken(securityToken);
        policyEnforcer.registerSecurityEvent(x509TokenSecurityEvent);

        List<XMLSecurityConstants.ContentType> protectionOrder = new LinkedList<XMLSecurityConstants.ContentType>();
        protectionOrder.add(XMLSecurityConstants.ContentType.SIGNATURE);

        SignedElementSecurityEvent signedElementSecurityEvent = new SignedElementSecurityEvent(getX509Token(WSSConstants.X509V3Token), false, protectionOrder);
        signedElementSecurityEvent.setElementPath(path);
        policyEnforcer.registerSecurityEvent(signedElementSecurityEvent);

        OperationSecurityEvent operationSecurityEvent = new OperationSecurityEvent();
        operationSecurityEvent.setOperation(new QName("definitions"));

        try {
            policyEnforcer.registerSecurityEvent(operationSecurityEvent);
            Assert.fail("Exception expected");
        } catch (WSSecurityException e) {
            Assert.assertTrue(e.getCause() instanceof PolicyViolationException);
            Assert.assertEquals(e.getCause().getMessage(), "\n" +
                    "Token /{http://schemas.xmlsoap.org/soap/envelope/}Envelope/{http://schemas.xmlsoap.org/soap/envelope/}Header/{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd}Security/{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd}BinarySecurityToken must be signed by its signature.");
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
        X509SecurityToken securityToken = getX509Token(WSSConstants.X509V3Token);
        List<QName> path = new ArrayList<QName>();
        path.addAll(WSSConstants.WSSE_SECURITY_HEADER_PATH);
        path.add(WSSConstants.TAG_wsse_BinarySecurityToken);
        securityToken.setElementPath(path);
        securityToken.addTokenUsage(SecurityToken.TokenUsage.MainSignature);
        x509TokenSecurityEvent.setSecurityToken(securityToken);

        List<XMLSecurityConstants.ContentType> protectionOrder = new LinkedList<XMLSecurityConstants.ContentType>();
        protectionOrder.add(XMLSecurityConstants.ContentType.SIGNATURE);

        SignedElementSecurityEvent signedElementSecurityEvent = new SignedElementSecurityEvent(getX509Token(WSSConstants.X509V3Token), false, protectionOrder);
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
            Assert.assertEquals(e.getCause().getMessage(), "\n" +
                    "Token /{http://schemas.xmlsoap.org/soap/envelope/}Envelope/{http://schemas.xmlsoap.org/soap/envelope/}Header/{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd}Security/{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd}BinarySecurityToken must be signed by its signature.");
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

        List<XMLSecurityConstants.ContentType> protectionOrder = new LinkedList<XMLSecurityConstants.ContentType>();
        protectionOrder.add(XMLSecurityConstants.ContentType.SIGNATURE);

        List<QName> bstPath = new ArrayList<QName>();
        bstPath.addAll(WSSConstants.WSSE_SECURITY_HEADER_PATH);
        bstPath.add(WSSConstants.TAG_wsse_BinarySecurityToken);

        List<QName> sigPath = new ArrayList<QName>();
        sigPath.addAll(WSSConstants.WSSE_SECURITY_HEADER_PATH);
        sigPath.add(WSSConstants.TAG_dsig_Signature);

        List<SecurityToken> securityTokens = new LinkedList<SecurityToken>();

        for (SecurityToken.TokenUsage tokenUsage : EnumSet.allOf(SecurityToken.TokenUsage.class)) {
            X509TokenSecurityEvent x509TokenSecurityEvent = new X509TokenSecurityEvent();
            X509SecurityToken securityToken = getX509Token(WSSConstants.X509V3Token);

            securityTokens.add(securityToken);

            securityToken.setElementPath(bstPath);
            securityToken.addTokenUsage(tokenUsage);
            x509TokenSecurityEvent.setSecurityToken(securityToken);
            policyEnforcer.registerSecurityEvent(x509TokenSecurityEvent);

            if (tokenUsage.name().contains("Signature") || tokenUsage.name().contains("Endorsing")) {
                SignedElementSecurityEvent signedElementSecurityEvent = new SignedElementSecurityEvent(securityToken, true, protectionOrder);
                signedElementSecurityEvent.setElementPath(bstPath);
                policyEnforcer.registerSecurityEvent(signedElementSecurityEvent);
            }
        }

        SecurityToken mainSignatureToken = null;
        Iterator<SecurityToken> securityTokenIterator = securityTokens.iterator();
        while (securityTokenIterator.hasNext()) {
            SecurityToken securityToken = securityTokenIterator.next();
            if (securityToken.getTokenUsages().contains(SecurityToken.TokenUsage.MainSignature)) {
                mainSignatureToken = securityToken;
                break;
            }
        }

        securityTokenIterator = securityTokens.iterator();
        while (securityTokenIterator.hasNext()) {
            SecurityToken securityToken = securityTokenIterator.next();
            if (securityToken.getTokenUsages().get(0).name().contains("Signed")) {
                SignedElementSecurityEvent signedElementSecurityEvent = new SignedElementSecurityEvent(mainSignatureToken, true, protectionOrder);
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
            Assert.assertEquals(e.getCause().getMessage(), "\n" +
                    "Token /{http://schemas.xmlsoap.org/soap/envelope/}Envelope/{http://schemas.xmlsoap.org/soap/envelope/}Header/{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd}Security/{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd}BinarySecurityToken must sign the main signature.");
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

        List<XMLSecurityConstants.ContentType> protectionOrder = new LinkedList<XMLSecurityConstants.ContentType>();
        protectionOrder.add(XMLSecurityConstants.ContentType.SIGNATURE);

        List<QName> bstPath = new ArrayList<QName>();
        bstPath.addAll(WSSConstants.WSSE_SECURITY_HEADER_PATH);
        bstPath.add(WSSConstants.TAG_wsse_BinarySecurityToken);

        List<QName> sigPath = new ArrayList<QName>();
        sigPath.addAll(WSSConstants.WSSE_SECURITY_HEADER_PATH);
        sigPath.add(WSSConstants.TAG_dsig_Signature);

        for (SecurityToken.TokenUsage tokenUsage : EnumSet.allOf(SecurityToken.TokenUsage.class)) {
            X509TokenSecurityEvent x509TokenSecurityEvent = new X509TokenSecurityEvent();
            X509SecurityToken securityToken = getX509Token(WSSConstants.X509V3Token);

            securityToken.setElementPath(bstPath);
            securityToken.addTokenUsage(tokenUsage);
            x509TokenSecurityEvent.setSecurityToken(securityToken);
            policyEnforcer.registerSecurityEvent(x509TokenSecurityEvent);

            if (tokenUsage.name().contains("Signature") || tokenUsage.name().contains("Endorsing")) {
                SignedElementSecurityEvent signedElementSecurityEvent = new SignedElementSecurityEvent(securityToken, true, protectionOrder);
                signedElementSecurityEvent.setElementPath(bstPath);
                policyEnforcer.registerSecurityEvent(signedElementSecurityEvent);
            }

            if (tokenUsage.name().contains("Endorsing")) {
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
            Assert.assertEquals(e.getCause().getMessage(), "\n" +
                    "Main signature must sign the Signed*Supporting-Tokens.");
        }
    }
}
