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

import java.util.LinkedList;
import java.util.List;

import javax.xml.namespace.QName;

import org.apache.wss4j.common.WSSPolicyException;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.policy.stax.enforcer.PolicyEnforcer;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.impl.securityToken.X509SecurityTokenImpl;
import org.apache.wss4j.stax.securityEvent.DerivedKeyTokenSecurityEvent;
import org.apache.wss4j.stax.securityEvent.OperationSecurityEvent;
import org.apache.wss4j.stax.securityEvent.SignedPartSecurityEvent;
import org.apache.wss4j.stax.securityEvent.X509TokenSecurityEvent;
import org.apache.wss4j.stax.securityToken.WSSecurityTokenConstants;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.securityEvent.ContentEncryptedElementSecurityEvent;
import org.apache.xml.security.stax.securityToken.InboundSecurityToken;
import org.junit.Assert;
import org.junit.Test;

public class DerivedKeyTests extends AbstractPolicyTestBase {

    @Test
    public void testDerivedKeyInitiatorTokenPolicy() throws Exception {
        String policyString =
                "<sp:AsymmetricBinding xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\" xmlns:sp3=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200802\">\n" +
                        "<wsp:Policy xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">\n" +
                        "<sp:InitiatorToken>\n" +
                        "   <wsp:Policy>\n" +
                        "       <sp:X509Token>\n" +
                        "           <sp:IssuerName>CN=transmitter,OU=swssf,C=CH</sp:IssuerName>\n" +
                        "           <wsp:Policy xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">\n" +
                        "               <sp:RequireDerivedKeys/>\n" +
                        "           </wsp:Policy>\n" +
                        "       </sp:X509Token>\n" +
                        "   </wsp:Policy>\n" +
                        "</sp:InitiatorToken>\n" +
                        "<sp:RecipientToken>\n" +
                        "   <wsp:Policy>\n" +
                        "       <sp:X509Token>\n" +
                        "           <sp:IssuerName>CN=transmitter,OU=swssf,C=CH</sp:IssuerName>\n" +
                        "           <wsp:Policy xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">\n" +
                        "               <sp:RequireDerivedKeys/>\n" +
                        "           </wsp:Policy>\n" +
                        "       </sp:X509Token>\n" +
                        "   </wsp:Policy>\n" +
                        "</sp:RecipientToken>\n" +
                        "   <sp:AlgorithmSuite>\n" +
                        "       <wsp:Policy>\n" +
                        "           <sp:Basic256/>\n" +
                        "       </wsp:Policy>\n" +
                        "   </sp:AlgorithmSuite>\n" +
                        "</wsp:Policy>\n" +
                        "</sp:AsymmetricBinding>";

        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);
        X509TokenSecurityEvent initiatorX509TokenSecurityEvent = new X509TokenSecurityEvent();
        X509SecurityTokenImpl securityToken = getX509Token(WSSecurityTokenConstants.X509V3Token);
        securityToken.addTokenUsage(WSSecurityTokenConstants.TokenUsage_MainSignature);
        initiatorX509TokenSecurityEvent.setSecurityToken(securityToken);

        DerivedKeyTokenSecurityEvent derivedKeyTokenSecurityEvent = new DerivedKeyTokenSecurityEvent();
        derivedKeyTokenSecurityEvent.setSecurityToken(getX509Token(WSSecurityTokenConstants.DerivedKeyToken));
        securityToken.addWrappedToken((InboundSecurityToken)derivedKeyTokenSecurityEvent.getSecurityToken());

        policyEnforcer.registerSecurityEvent(initiatorX509TokenSecurityEvent);

        X509TokenSecurityEvent recipientX509TokenSecurityEvent = new X509TokenSecurityEvent();
        securityToken = getX509Token(WSSecurityTokenConstants.X509V3Token);
        securityToken.addTokenUsage(WSSecurityTokenConstants.TokenUsage_MainEncryption);
        recipientX509TokenSecurityEvent.setSecurityToken(securityToken);

        derivedKeyTokenSecurityEvent = new DerivedKeyTokenSecurityEvent();
        derivedKeyTokenSecurityEvent.setSecurityToken(getX509Token(WSSecurityTokenConstants.DerivedKeyToken));
        securityToken.addWrappedToken((InboundSecurityToken)derivedKeyTokenSecurityEvent.getSecurityToken());

        policyEnforcer.registerSecurityEvent(recipientX509TokenSecurityEvent);

        List<XMLSecurityConstants.ContentType> protectionOrder = new LinkedList<>();
        protectionOrder.add(XMLSecurityConstants.ContentType.SIGNATURE);
        protectionOrder.add(XMLSecurityConstants.ContentType.ENCRYPTION);
        SignedPartSecurityEvent signedPartSecurityEvent =
                new SignedPartSecurityEvent(
                        (InboundSecurityToken)recipientX509TokenSecurityEvent.getSecurityToken(), true, protectionOrder);
        signedPartSecurityEvent.setElementPath(WSSConstants.SOAP_11_BODY_PATH);
        policyEnforcer.registerSecurityEvent(signedPartSecurityEvent);

        ContentEncryptedElementSecurityEvent contentEncryptedElementSecurityEvent =
                new ContentEncryptedElementSecurityEvent(
                        (InboundSecurityToken)recipientX509TokenSecurityEvent.getSecurityToken(), true, protectionOrder);
        contentEncryptedElementSecurityEvent.setElementPath(WSSConstants.SOAP_11_BODY_PATH);
        policyEnforcer.registerSecurityEvent(contentEncryptedElementSecurityEvent);

        OperationSecurityEvent operationSecurityEvent = new OperationSecurityEvent();
        operationSecurityEvent.setOperation(new QName("definitions"));

        policyEnforcer.registerSecurityEvent(operationSecurityEvent);
        policyEnforcer.doFinal();
    }

    @Test
    public void testDerivedKeyInitiatorTokenPolicyNegative() throws Exception {
        String policyString =
                "<sp:AsymmetricBinding xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\" xmlns:sp3=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200802\">\n" +
                        "<wsp:Policy xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">\n" +
                        "<sp:InitiatorToken>\n" +
                        "   <wsp:Policy>\n" +
                        "       <sp:X509Token>\n" +
                        "           <sp:IssuerName>CN=transmitter,OU=swssf,C=CH</sp:IssuerName>\n" +
                        "           <wsp:Policy xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">\n" +
                        "               <sp:RequireDerivedKeys/>\n" +
                        "           </wsp:Policy>\n" +
                        "       </sp:X509Token>\n" +
                        "   </wsp:Policy>\n" +
                        "</sp:InitiatorToken>\n" +
                        "<sp:RecipientToken>\n" +
                        "   <wsp:Policy>\n" +
                        "       <sp:X509Token>\n" +
                        "           <sp:IssuerName>CN=transmitter,OU=swssf,C=CH</sp:IssuerName>\n" +
                        "           <wsp:Policy xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">\n" +
                        "               <sp:RequireDerivedKeys/>\n" +
                        "           </wsp:Policy>\n" +
                        "       </sp:X509Token>\n" +
                        "   </wsp:Policy>\n" +
                        "</sp:RecipientToken>\n" +
                        "   <sp:AlgorithmSuite>\n" +
                        "       <wsp:Policy>\n" +
                        "           <sp:Basic256/>\n" +
                        "       </wsp:Policy>\n" +
                        "   </sp:AlgorithmSuite>\n" +
                        "</wsp:Policy>\n" +
                        "</sp:AsymmetricBinding>";

        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);
        X509TokenSecurityEvent initiatorX509TokenSecurityEvent = new X509TokenSecurityEvent();
        X509SecurityTokenImpl securityToken = getX509Token(WSSecurityTokenConstants.X509V3Token);
        securityToken.addTokenUsage(WSSecurityTokenConstants.TokenUsage_MainSignature);
        initiatorX509TokenSecurityEvent.setSecurityToken(securityToken);
        policyEnforcer.registerSecurityEvent(initiatorX509TokenSecurityEvent);

        X509TokenSecurityEvent recipientX509TokenSecurityEvent = new X509TokenSecurityEvent();
        securityToken = getX509Token(WSSecurityTokenConstants.X509V3Token);
        securityToken.addTokenUsage(WSSecurityTokenConstants.TokenUsage_MainEncryption);
        recipientX509TokenSecurityEvent.setSecurityToken(securityToken);

        DerivedKeyTokenSecurityEvent derivedKeyTokenSecurityEvent = new DerivedKeyTokenSecurityEvent();
        derivedKeyTokenSecurityEvent.setSecurityToken(getX509Token(WSSecurityTokenConstants.DerivedKeyToken));
        securityToken.addWrappedToken((InboundSecurityToken)derivedKeyTokenSecurityEvent.getSecurityToken());

        policyEnforcer.registerSecurityEvent(recipientX509TokenSecurityEvent);

        List<XMLSecurityConstants.ContentType> protectionOrder = new LinkedList<>();
        protectionOrder.add(XMLSecurityConstants.ContentType.SIGNATURE);
        protectionOrder.add(XMLSecurityConstants.ContentType.ENCRYPTION);
        SignedPartSecurityEvent signedPartSecurityEvent =
                new SignedPartSecurityEvent(
                        (InboundSecurityToken)recipientX509TokenSecurityEvent.getSecurityToken(), true, protectionOrder);
        signedPartSecurityEvent.setElementPath(WSSConstants.SOAP_11_BODY_PATH);
        policyEnforcer.registerSecurityEvent(signedPartSecurityEvent);

        ContentEncryptedElementSecurityEvent contentEncryptedElementSecurityEvent =
                new ContentEncryptedElementSecurityEvent(
                        (InboundSecurityToken)recipientX509TokenSecurityEvent.getSecurityToken(), true, protectionOrder);
        contentEncryptedElementSecurityEvent.setElementPath(WSSConstants.SOAP_11_BODY_PATH);
        policyEnforcer.registerSecurityEvent(contentEncryptedElementSecurityEvent);

        OperationSecurityEvent operationSecurityEvent = new OperationSecurityEvent();
        operationSecurityEvent.setOperation(new QName("definitions"));
        try {
            policyEnforcer.registerSecurityEvent(operationSecurityEvent);
            Assert.fail("Exception expected");
        } catch (WSSecurityException e) {
            Assert.assertEquals(e.getMessage(),
                    "Derived key must be used");
            Assert.assertEquals(e.getFaultCode(), WSSecurityException.INVALID_SECURITY);
        }
    }

    @Test
    public void testDerivedKeyRecipientTokenPolicyNegative() throws Exception {
        String policyString =
                "<sp:AsymmetricBinding xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\" xmlns:sp3=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200802\">\n" +
                        "<wsp:Policy xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">\n" +
                        "<sp:InitiatorToken>\n" +
                        "   <wsp:Policy>\n" +
                        "       <sp:X509Token>\n" +
                        "           <sp:IssuerName>CN=transmitter,OU=swssf,C=CH</sp:IssuerName>\n" +
                        "           <wsp:Policy xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">\n" +
                        "               <sp:RequireDerivedKeys/>\n" +
                        "           </wsp:Policy>\n" +
                        "       </sp:X509Token>\n" +
                        "   </wsp:Policy>\n" +
                        "</sp:InitiatorToken>\n" +
                        "<sp:RecipientToken>\n" +
                        "   <wsp:Policy>\n" +
                        "       <sp:X509Token>\n" +
                        "           <sp:IssuerName>CN=transmitter,OU=swssf,C=CH</sp:IssuerName>\n" +
                        "           <wsp:Policy xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">\n" +
                        "               <sp:RequireDerivedKeys/>\n" +
                        "           </wsp:Policy>\n" +
                        "       </sp:X509Token>\n" +
                        "   </wsp:Policy>\n" +
                        "</sp:RecipientToken>\n" +
                        "   <sp:AlgorithmSuite>\n" +
                        "       <wsp:Policy>\n" +
                        "           <sp:Basic256/>\n" +
                        "       </wsp:Policy>\n" +
                        "   </sp:AlgorithmSuite>\n" +
                        "</wsp:Policy>\n" +
                        "</sp:AsymmetricBinding>";

        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);
        X509TokenSecurityEvent initiatorX509TokenSecurityEvent = new X509TokenSecurityEvent();
        X509SecurityTokenImpl securityToken = getX509Token(WSSecurityTokenConstants.X509V3Token);
        securityToken.addTokenUsage(WSSecurityTokenConstants.TokenUsage_MainSignature);
        initiatorX509TokenSecurityEvent.setSecurityToken(securityToken);

        DerivedKeyTokenSecurityEvent derivedKeyTokenSecurityEvent = new DerivedKeyTokenSecurityEvent();
        derivedKeyTokenSecurityEvent.setSecurityToken(getX509Token(WSSecurityTokenConstants.DerivedKeyToken));
        securityToken.addWrappedToken((InboundSecurityToken)derivedKeyTokenSecurityEvent.getSecurityToken());

        policyEnforcer.registerSecurityEvent(initiatorX509TokenSecurityEvent);

        X509TokenSecurityEvent recipientX509TokenSecurityEvent = new X509TokenSecurityEvent();
        securityToken = getX509Token(WSSecurityTokenConstants.X509V3Token);
        securityToken.addTokenUsage(WSSecurityTokenConstants.TokenUsage_MainEncryption);
        recipientX509TokenSecurityEvent.setSecurityToken(securityToken);
        policyEnforcer.registerSecurityEvent(recipientX509TokenSecurityEvent);

        List<XMLSecurityConstants.ContentType> protectionOrder = new LinkedList<>();
        protectionOrder.add(XMLSecurityConstants.ContentType.SIGNATURE);
        protectionOrder.add(XMLSecurityConstants.ContentType.ENCRYPTION);
        SignedPartSecurityEvent signedPartSecurityEvent =
                new SignedPartSecurityEvent(
                        (InboundSecurityToken)recipientX509TokenSecurityEvent.getSecurityToken(), true, protectionOrder);
        signedPartSecurityEvent.setElementPath(WSSConstants.SOAP_11_BODY_PATH);
        policyEnforcer.registerSecurityEvent(signedPartSecurityEvent);

        ContentEncryptedElementSecurityEvent contentEncryptedElementSecurityEvent =
                new ContentEncryptedElementSecurityEvent(
                        (InboundSecurityToken)recipientX509TokenSecurityEvent.getSecurityToken(), true, protectionOrder);
        contentEncryptedElementSecurityEvent.setElementPath(WSSConstants.SOAP_11_BODY_PATH);
        policyEnforcer.registerSecurityEvent(contentEncryptedElementSecurityEvent);

        OperationSecurityEvent operationSecurityEvent = new OperationSecurityEvent();
        operationSecurityEvent.setOperation(new QName("definitions"));
        try {
            policyEnforcer.registerSecurityEvent(operationSecurityEvent);
            Assert.fail("Exception expected");
        } catch (WSSecurityException e) {
            Assert.assertEquals(e.getMessage(),
                    "Derived key must be used");
            Assert.assertEquals(e.getFaultCode(), WSSecurityException.INVALID_SECURITY);
        }
    }

    @Test
    public void testDerivedKeySupportingTokenPolicy() throws Exception {
        String policyString =
                "<sp:SupportingTokens xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\" xmlns:sp3=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200802\">\n" +
                        "<wsp:Policy xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">\n" +
                        "       <sp:X509Token>\n" +
                        "           <sp:IssuerName>CN=transmitter,OU=swssf,C=CH</sp:IssuerName>\n" +
                        "           <wsp:Policy xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">\n" +
                        "               <sp:RequireDerivedKeys/>\n" +
                        "           </wsp:Policy>\n" +
                        "       </sp:X509Token>\n" +
                        "   </wsp:Policy>\n" +
                        "</sp:SupportingTokens>";

        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);
        X509TokenSecurityEvent x509TokenSecurityEvent = new X509TokenSecurityEvent();
        X509SecurityTokenImpl securityToken = getX509Token(WSSecurityTokenConstants.X509V3Token);
        securityToken.addTokenUsage(WSSecurityTokenConstants.TokenUsage_SupportingTokens);
        x509TokenSecurityEvent.setSecurityToken(securityToken);

        DerivedKeyTokenSecurityEvent derivedKeyTokenSecurityEvent = new DerivedKeyTokenSecurityEvent();
        derivedKeyTokenSecurityEvent.setSecurityToken(getX509Token(WSSecurityTokenConstants.DerivedKeyToken));
        securityToken.addWrappedToken((InboundSecurityToken)derivedKeyTokenSecurityEvent.getSecurityToken());

        policyEnforcer.registerSecurityEvent(x509TokenSecurityEvent);

        OperationSecurityEvent operationSecurityEvent = new OperationSecurityEvent();
        operationSecurityEvent.setOperation(new QName("definitions"));
        policyEnforcer.registerSecurityEvent(operationSecurityEvent);

        policyEnforcer.doFinal();
    }

    @Test
    public void testDerivedKeySupportingTokenPolicyNegative() throws Exception {
        String policyString =
                "<sp:SupportingTokens xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\" xmlns:sp3=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200802\">\n" +
                        "<wsp:Policy xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">\n" +
                        "       <sp:X509Token>\n" +
                        "           <sp:IssuerName>CN=transmitter,OU=swssf,C=CH</sp:IssuerName>\n" +
                        "           <wsp:Policy xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">\n" +
                        "               <sp:RequireDerivedKeys/>\n" +
                        "           </wsp:Policy>\n" +
                        "       </sp:X509Token>\n" +
                        "   </wsp:Policy>\n" +
                        "</sp:SupportingTokens>";

        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);
        X509TokenSecurityEvent x509TokenSecurityEvent = new X509TokenSecurityEvent();
        X509SecurityTokenImpl securityToken = getX509Token(WSSecurityTokenConstants.X509V1Token);
        securityToken.addTokenUsage(WSSecurityTokenConstants.TokenUsage_SupportingTokens);
        x509TokenSecurityEvent.setSecurityToken(securityToken);
        policyEnforcer.registerSecurityEvent(x509TokenSecurityEvent);

        OperationSecurityEvent operationSecurityEvent = new OperationSecurityEvent();
        operationSecurityEvent.setOperation(new QName("definitions"));
        try {
            policyEnforcer.registerSecurityEvent(operationSecurityEvent);
            Assert.fail("Exception expected");
        } catch (WSSecurityException e) {
            Assert.assertEquals(e.getMessage(),
                    "Derived key must be used");
            Assert.assertEquals(e.getFaultCode(), WSSecurityException.INVALID_SECURITY);
        }
    }

    @Test
    public void testDerivedKeySupportingTokenPolicyAdditionalToken() throws Exception {
        String policyString =
                "<sp:SupportingTokens xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\" xmlns:sp3=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200802\">\n" +
                        "<wsp:Policy xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">\n" +
                        "       <sp:X509Token>\n" +
                        "           <sp:IssuerName>CN=transmitter,OU=swssf,C=CH</sp:IssuerName>\n" +
                        "           <wsp:Policy xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">\n" +
                        "               <sp:RequireDerivedKeys/>\n" +
                        "           </wsp:Policy>\n" +
                        "       </sp:X509Token>\n" +
                        "   </wsp:Policy>\n" +
                        "</sp:SupportingTokens>";

        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);

        X509TokenSecurityEvent x509TokenSecurityEvent = new X509TokenSecurityEvent();
        X509SecurityTokenImpl securityToken = getX509Token(WSSecurityTokenConstants.X509V3Token);
        securityToken.addTokenUsage(WSSecurityTokenConstants.TokenUsage_SupportingTokens);
        x509TokenSecurityEvent.setSecurityToken(securityToken);

        DerivedKeyTokenSecurityEvent derivedKeyTokenSecurityEvent = new DerivedKeyTokenSecurityEvent();
        derivedKeyTokenSecurityEvent.setSecurityToken(getX509Token(WSSecurityTokenConstants.DerivedKeyToken));
        securityToken.addWrappedToken((InboundSecurityToken)derivedKeyTokenSecurityEvent.getSecurityToken());

        policyEnforcer.registerSecurityEvent(x509TokenSecurityEvent);

        x509TokenSecurityEvent = new X509TokenSecurityEvent();
        securityToken = getX509Token(WSSecurityTokenConstants.X509V3Token);
        securityToken.addTokenUsage(WSSecurityTokenConstants.TokenUsage_SupportingTokens);
        x509TokenSecurityEvent.setSecurityToken(securityToken);

        derivedKeyTokenSecurityEvent = new DerivedKeyTokenSecurityEvent();
        derivedKeyTokenSecurityEvent.setSecurityToken(getX509Token(WSSecurityTokenConstants.DerivedKeyToken));
        securityToken.addWrappedToken((InboundSecurityToken)derivedKeyTokenSecurityEvent.getSecurityToken());

        policyEnforcer.registerSecurityEvent(x509TokenSecurityEvent);

        OperationSecurityEvent operationSecurityEvent = new OperationSecurityEvent();
        operationSecurityEvent.setOperation(new QName("definitions"));
        policyEnforcer.registerSecurityEvent(operationSecurityEvent);

        policyEnforcer.doFinal();
    }

    @Test
    public void testDerivedKeySupportingTokenPolicyAdditionalTokenNegative() throws Exception {
        String policyString =
                "<sp:SupportingTokens xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\" xmlns:sp3=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200802\">\n" +
                        "<wsp:Policy xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">\n" +
                        "       <sp:X509Token>\n" +
                        "           <sp:IssuerName>CN=transmitter,OU=swssf,C=CH</sp:IssuerName>\n" +
                        "           <wsp:Policy xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">\n" +
                        "               <sp:RequireDerivedKeys/>\n" +
                        "           </wsp:Policy>\n" +
                        "       </sp:X509Token>\n" +
                        "   </wsp:Policy>\n" +
                        "</sp:SupportingTokens>";

        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);

        X509TokenSecurityEvent x509TokenSecurityEvent = new X509TokenSecurityEvent();
        X509SecurityTokenImpl securityToken = getX509Token(WSSecurityTokenConstants.X509V1Token);
        securityToken.addTokenUsage(WSSecurityTokenConstants.TokenUsage_SupportingTokens);
        x509TokenSecurityEvent.setSecurityToken(securityToken);
        policyEnforcer.registerSecurityEvent(x509TokenSecurityEvent);

        x509TokenSecurityEvent = new X509TokenSecurityEvent();
        securityToken = getX509Token(WSSecurityTokenConstants.X509V1Token);
        securityToken.addTokenUsage(WSSecurityTokenConstants.TokenUsage_SupportingTokens);
        x509TokenSecurityEvent.setSecurityToken(securityToken);
        policyEnforcer.registerSecurityEvent(x509TokenSecurityEvent);

        OperationSecurityEvent operationSecurityEvent = new OperationSecurityEvent();
        operationSecurityEvent.setOperation(new QName("definitions"));

        try {
            policyEnforcer.registerSecurityEvent(operationSecurityEvent);
            Assert.fail("Exception expected");
        } catch (WSSecurityException e) {
            Assert.assertTrue(e.getCause() instanceof WSSPolicyException);
        }
    }

    @Test
    public void testDerivedKeySupportingTokenPolicyAdditionalTokenLastIgnore() throws Exception {
        String policyString =
                "<sp:SupportingTokens xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\" xmlns:sp3=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200802\">\n" +
                        "<wsp:Policy xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">\n" +
                        "       <sp:X509Token>\n" +
                        "           <sp:IssuerName>CN=transmitter,OU=swssf,C=CH</sp:IssuerName>\n" +
                        "           <wsp:Policy xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">\n" +
                        "               <sp:RequireDerivedKeys/>\n" +
                        "           </wsp:Policy>\n" +
                        "       </sp:X509Token>\n" +
                        "   </wsp:Policy>\n" +
                        "</sp:SupportingTokens>";

        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);

        X509TokenSecurityEvent x509TokenSecurityEvent = new X509TokenSecurityEvent();
        X509SecurityTokenImpl securityToken = getX509Token(WSSecurityTokenConstants.X509V3Token);
        securityToken.addTokenUsage(WSSecurityTokenConstants.TokenUsage_SupportingTokens);
        x509TokenSecurityEvent.setSecurityToken(securityToken);

        DerivedKeyTokenSecurityEvent derivedKeyTokenSecurityEvent = new DerivedKeyTokenSecurityEvent();
        derivedKeyTokenSecurityEvent.setSecurityToken(getX509Token(WSSecurityTokenConstants.DerivedKeyToken));
        securityToken.addWrappedToken((InboundSecurityToken)derivedKeyTokenSecurityEvent.getSecurityToken());

        policyEnforcer.registerSecurityEvent(x509TokenSecurityEvent);

        x509TokenSecurityEvent = new X509TokenSecurityEvent();
        securityToken = getX509Token(WSSecurityTokenConstants.X509V1Token);
        securityToken.addTokenUsage(WSSecurityTokenConstants.TokenUsage_SupportingTokens);
        x509TokenSecurityEvent.setSecurityToken(securityToken);
        policyEnforcer.registerSecurityEvent(x509TokenSecurityEvent);

        OperationSecurityEvent operationSecurityEvent = new OperationSecurityEvent();
        operationSecurityEvent.setOperation(new QName("definitions"));
        policyEnforcer.registerSecurityEvent(operationSecurityEvent);

        policyEnforcer.doFinal();
    }

    @Test
    public void testDerivedKeySupportingTokenPolicyAdditionalTokenFirstIgnore() throws Exception {
        String policyString =
                "<sp:SupportingTokens xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\" xmlns:sp3=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200802\">\n" +
                        "<wsp:Policy xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">\n" +
                        "       <sp:X509Token>\n" +
                        "           <sp:IssuerName>CN=transmitter,OU=swssf,C=CH</sp:IssuerName>\n" +
                        "           <wsp:Policy xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">\n" +
                        "               <sp:RequireDerivedKeys/>\n" +
                        "           </wsp:Policy>\n" +
                        "       </sp:X509Token>\n" +
                        "   </wsp:Policy>\n" +
                        "</sp:SupportingTokens>";

        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);

        X509TokenSecurityEvent x509TokenSecurityEvent = new X509TokenSecurityEvent();
        X509SecurityTokenImpl securityToken = getX509Token(WSSecurityTokenConstants.X509V1Token);
        securityToken.addTokenUsage(WSSecurityTokenConstants.TokenUsage_SupportingTokens);
        x509TokenSecurityEvent.setSecurityToken(securityToken);
        policyEnforcer.registerSecurityEvent(x509TokenSecurityEvent);

        x509TokenSecurityEvent = new X509TokenSecurityEvent();
        securityToken = getX509Token(WSSecurityTokenConstants.X509V3Token);
        securityToken.addTokenUsage(WSSecurityTokenConstants.TokenUsage_SupportingTokens);
        x509TokenSecurityEvent.setSecurityToken(securityToken);

        DerivedKeyTokenSecurityEvent derivedKeyTokenSecurityEvent = new DerivedKeyTokenSecurityEvent();
        derivedKeyTokenSecurityEvent.setSecurityToken(getX509Token(WSSecurityTokenConstants.DerivedKeyToken));
        securityToken.addWrappedToken((InboundSecurityToken)derivedKeyTokenSecurityEvent.getSecurityToken());

        policyEnforcer.registerSecurityEvent(x509TokenSecurityEvent);

        OperationSecurityEvent operationSecurityEvent = new OperationSecurityEvent();
        operationSecurityEvent.setOperation(new QName("definitions"));
        policyEnforcer.registerSecurityEvent(operationSecurityEvent);

        policyEnforcer.doFinal();
    }
}
