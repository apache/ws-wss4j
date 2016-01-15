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

import org.apache.wss4j.policy.stax.enforcer.PolicyEnforcer;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.impl.securityToken.X509SecurityTokenImpl;
import org.apache.wss4j.stax.securityEvent.OperationSecurityEvent;
import org.apache.wss4j.stax.securityEvent.SecurityContextTokenSecurityEvent;
import org.apache.wss4j.stax.securityEvent.SignedPartSecurityEvent;
import org.apache.wss4j.stax.securityToken.WSSecurityTokenConstants;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.securityEvent.ContentEncryptedElementSecurityEvent;
import org.apache.xml.security.stax.securityToken.InboundSecurityToken;
import org.junit.Test;

public class SpnegoContextTokenTest extends AbstractPolicyTestBase {

    @Test
    public void testPolicy() throws Exception {
        String policyString =
                "<sp:AsymmetricBinding xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\" xmlns:sp3=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200802\">\n" +
                        "<wsp:Policy xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">\n" +
                        "<sp:InitiatorToken>\n" +
                        "   <wsp:Policy>\n" +
                        "       <sp:SpnegoContextToken>\n" +
                        "           <sp:IssuerName>xs:anyURI</sp:IssuerName>\n" +
                        "           <wsp:Policy xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">\n" +
                        "               <sp:MustNotSendCancel/>\n" +
                        "           </wsp:Policy>\n" +
                        "       </sp:SpnegoContextToken>\n" +
                        "   </wsp:Policy>\n" +
                        "</sp:InitiatorToken>\n" +
                        "<sp:RecipientToken>\n" +
                        "   <wsp:Policy>\n" +
                        "       <sp:SpnegoContextToken>\n" +
                        "           <sp:IssuerName>xs:anyURI</sp:IssuerName>\n" +
                        "           <wsp:Policy xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">\n" +
                        "               <sp:MustNotSendCancel/>\n" +
                        "           </wsp:Policy>\n" +
                        "       </sp:SpnegoContextToken>\n" +
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
        SecurityContextTokenSecurityEvent initiatorTokenSecurityEvent = new SecurityContextTokenSecurityEvent();
        initiatorTokenSecurityEvent.setIssuerName("xs:anyURI");
        X509SecurityTokenImpl securityToken = getX509Token(WSSecurityTokenConstants.X509V3Token);
        securityToken.addTokenUsage(WSSecurityTokenConstants.TOKENUSAGE_MAIN_SIGNATURE);
        initiatorTokenSecurityEvent.setSecurityToken(securityToken);
        policyEnforcer.registerSecurityEvent(initiatorTokenSecurityEvent);

        SecurityContextTokenSecurityEvent recipientTokenSecurityEvent = new SecurityContextTokenSecurityEvent();
        recipientTokenSecurityEvent.setIssuerName("xs:anyURI");
        securityToken = getX509Token(WSSecurityTokenConstants.X509V3Token);
        securityToken.addTokenUsage(WSSecurityTokenConstants.TOKENUSAGE_MAIN_ENCRYPTION);
        recipientTokenSecurityEvent.setSecurityToken(securityToken);
        policyEnforcer.registerSecurityEvent(recipientTokenSecurityEvent);

        List<XMLSecurityConstants.ContentType> protectionOrder = new LinkedList<>();
        protectionOrder.add(XMLSecurityConstants.ContentType.SIGNATURE);
        protectionOrder.add(XMLSecurityConstants.ContentType.ENCRYPTION);
        SignedPartSecurityEvent signedPartSecurityEvent =
                new SignedPartSecurityEvent(
                        (InboundSecurityToken)recipientTokenSecurityEvent.getSecurityToken(), true, protectionOrder);
        signedPartSecurityEvent.setElementPath(WSSConstants.SOAP_11_BODY_PATH);
        policyEnforcer.registerSecurityEvent(signedPartSecurityEvent);

        ContentEncryptedElementSecurityEvent contentEncryptedElementSecurityEvent =
                new ContentEncryptedElementSecurityEvent(
                        (InboundSecurityToken)recipientTokenSecurityEvent.getSecurityToken(), true, protectionOrder);
        contentEncryptedElementSecurityEvent.setElementPath(WSSConstants.SOAP_11_BODY_PATH);
        policyEnforcer.registerSecurityEvent(contentEncryptedElementSecurityEvent);

        OperationSecurityEvent operationSecurityEvent = new OperationSecurityEvent();
        operationSecurityEvent.setOperation(new QName("definitions"));
        policyEnforcer.registerSecurityEvent(operationSecurityEvent);

        policyEnforcer.doFinal();
    }

    //todo more tests
}
