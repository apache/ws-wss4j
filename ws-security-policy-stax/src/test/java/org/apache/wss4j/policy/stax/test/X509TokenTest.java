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

import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.policy.stax.PolicyEnforcer;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.securityToken.WSSecurityTokenConstants;
import org.apache.wss4j.stax.impl.securityToken.X509SecurityTokenImpl;
import org.apache.wss4j.stax.securityEvent.OperationSecurityEvent;
import org.apache.wss4j.stax.securityEvent.SignedPartSecurityEvent;
import org.apache.wss4j.stax.securityEvent.X509TokenSecurityEvent;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.securityEvent.ContentEncryptedElementSecurityEvent;
import org.apache.xml.security.stax.securityToken.InboundSecurityToken;
import org.testng.Assert;
import org.testng.annotations.Test;

import javax.xml.namespace.QName;
import java.util.LinkedList;
import java.util.List;

public class X509TokenTest extends AbstractPolicyTestBase {

    @Test
    public void testPolicy() throws Exception {
        String policyString =
                "<sp:AsymmetricBinding xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\" xmlns:sp3=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200802\">\n" +
                        "<wsp:Policy xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">\n" +
                        "<sp:InitiatorToken>\n" +
                        "   <wsp:Policy>\n" +
                        "       <sp:X509Token>\n" +
                        "           <sp:IssuerName>CN=transmitter,OU=swssf,C=CH</sp:IssuerName>\n" +
                        "           <wsp:Policy xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">\n" +
                        "               <sp:RequireThumbprintReference/>\n" +
                        "               <sp:WssX509V3Token11/>\n" +
                        "           </wsp:Policy>\n" +
                        "       </sp:X509Token>\n" +
                        "   </wsp:Policy>\n" +
                        "</sp:InitiatorToken>\n" +
                        "<sp:RecipientToken>\n" +
                        "   <wsp:Policy>\n" +
                        "       <sp:X509Token>\n" +
                        "           <sp:IssuerName>CN=transmitter,OU=swssf,C=CH</sp:IssuerName>\n" +
                        "           <wsp:Policy xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">\n" +
                        "               <sp:RequireThumbprintReference/>\n" +
                        "               <sp:WssX509V3Token11/>\n" +
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
        policyEnforcer.registerSecurityEvent(recipientX509TokenSecurityEvent);

        List<XMLSecurityConstants.ContentType> protectionOrder = new LinkedList<XMLSecurityConstants.ContentType>();
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
    public void testPolicyNegative() throws Exception {
        String policyString =
                "<sp:AsymmetricBinding xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\" xmlns:sp3=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200802\">\n" +
                        "<wsp:Policy xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">\n" +
                        "<sp:InitiatorToken>\n" +
                        "   <wsp:Policy>\n" +
                        "       <sp:X509Token>\n" +
                        "           <sp:IssuerName>CN=transmitter,OU=swssf,C=CH</sp:IssuerName>\n" +
                        "           <wsp:Policy xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">\n" +
                        "               <sp:RequireThumbprintReference/>\n" +
                        "               <sp:WssX509V3Token11/>\n" +
                        "           </wsp:Policy>\n" +
                        "       </sp:X509Token>\n" +
                        "   </wsp:Policy>\n" +
                        "</sp:InitiatorToken>\n" +
                        "<sp:RecipientToken>\n" +
                        "   <wsp:Policy>\n" +
                        "       <sp:X509Token>\n" +
                        "           <sp:IssuerName>CN=transmitter,OU=swssf,C=CH</sp:IssuerName>\n" +
                        "           <wsp:Policy xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">\n" +
                        "               <sp:RequireThumbprintReference/>\n" +
                        "               <sp:WssX509V3Token11/>\n" +
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
        X509SecurityTokenImpl securityToken = getX509Token(WSSecurityTokenConstants.X509V1Token);
        securityToken.addTokenUsage(WSSecurityTokenConstants.TokenUsage_MainSignature);
        initiatorX509TokenSecurityEvent.setSecurityToken(securityToken);
        policyEnforcer.registerSecurityEvent(initiatorX509TokenSecurityEvent);

        X509TokenSecurityEvent recipientX509TokenSecurityEvent = new X509TokenSecurityEvent();
        securityToken = getX509Token(WSSecurityTokenConstants.X509V3Token);
        securityToken.addTokenUsage(WSSecurityTokenConstants.TokenUsage_MainEncryption);
        recipientX509TokenSecurityEvent.setSecurityToken(securityToken);
        policyEnforcer.registerSecurityEvent(recipientX509TokenSecurityEvent);

        List<XMLSecurityConstants.ContentType> protectionOrder = new LinkedList<XMLSecurityConstants.ContentType>();
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
                    "X509Certificate Version 3 mismatch; Policy enforces WssX509V3Token11");
            Assert.assertEquals(e.getFaultCode(), WSSecurityException.INVALID_SECURITY);
        }
    }
}
