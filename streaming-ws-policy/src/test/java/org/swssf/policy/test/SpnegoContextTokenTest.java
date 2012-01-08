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
import org.swssf.wss.ext.WSSConstants;
import org.swssf.wss.impl.securityToken.X509SecurityToken;
import org.swssf.wss.securityEvent.*;
import org.swssf.xmlsec.ext.XMLSecurityException;
import org.testng.annotations.Test;

import javax.xml.namespace.QName;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
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
                        "</wsp:Policy>\n" +
                        "</sp:AsymmetricBinding>";

        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);
        SpnegoContextTokenSecurityEvent initiatorTokenSecurityEvent = new SpnegoContextTokenSecurityEvent();
        initiatorTokenSecurityEvent.setIssuerName("xs:anyURI");
        initiatorTokenSecurityEvent.setSecurityToken(new X509SecurityToken(WSSConstants.X509V3Token, null, null, null, "1", null, null) {
            @Override
            protected String getAlias() throws XMLSecurityException {
                return null;
            }
        });
        initiatorTokenSecurityEvent.setTokenUsage(TokenSecurityEvent.TokenUsage.Signature);
        policyEnforcer.registerSecurityEvent(initiatorTokenSecurityEvent);

        SpnegoContextTokenSecurityEvent recipientTokenSecurityEvent = new SpnegoContextTokenSecurityEvent();
        recipientTokenSecurityEvent.setSecurityToken(new X509SecurityToken(WSSConstants.X509V3Token, null, null, null, "1", null, null) {
            @Override
            protected String getAlias() throws XMLSecurityException {
                return null;
            }
        });
        recipientTokenSecurityEvent.setTokenUsage(TokenSecurityEvent.TokenUsage.Encryption);
        policyEnforcer.registerSecurityEvent(recipientTokenSecurityEvent);

        SignedPartSecurityEvent signedPartSecurityEvent = new SignedPartSecurityEvent(recipientTokenSecurityEvent.getSecurityToken(), true);
        signedPartSecurityEvent.setElement(WSSConstants.TAG_soap11_Body);
        policyEnforcer.registerSecurityEvent(signedPartSecurityEvent);

        ContentEncryptedElementSecurityEvent contentEncryptedElementSecurityEvent = new ContentEncryptedElementSecurityEvent(recipientTokenSecurityEvent.getSecurityToken(), true, true);
        contentEncryptedElementSecurityEvent.setElement(WSSConstants.TAG_soap11_Body);
        policyEnforcer.registerSecurityEvent(contentEncryptedElementSecurityEvent);

        OperationSecurityEvent operationSecurityEvent = new OperationSecurityEvent();
        operationSecurityEvent.setOperation(new QName("definitions"));
        policyEnforcer.registerSecurityEvent(operationSecurityEvent);

        policyEnforcer.doFinal();
    }

    //todo more tests
}
