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

import javax.xml.namespace.QName;

import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.policy.stax.PolicyViolationException;
import org.apache.wss4j.policy.stax.enforcer.PolicyEnforcer;
import org.apache.wss4j.stax.impl.securityToken.HttpsSecurityTokenImpl;
import org.apache.wss4j.stax.securityEvent.HttpsTokenSecurityEvent;
import org.apache.wss4j.stax.securityEvent.OperationSecurityEvent;
import org.apache.wss4j.stax.securityToken.WSSecurityTokenConstants;
import org.junit.Assert;
import org.junit.Test;

public class HttpsTokenTest extends AbstractPolicyTestBase {

    @Test
    public void testPolicy() throws Exception {
        String policyString =
                "<sp:TransportBinding xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\" xmlns:sp3=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200802\">\n" +
                        "<wsp:Policy xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">\n" +
                        "<sp:TransportToken>\n" +
                        "   <wsp:Policy>\n" +
                        "       <sp:HttpsToken>\n" +
                        "       <sp:IssuerName>xs:anyURI</sp:IssuerName>\n" +
                        "       <wsp:Policy xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">\n" +
                        "           <sp:RequireClientCertificate/>\n" +
                        "       </wsp:Policy>\n" +
                        "       </sp:HttpsToken>" +
                        "   </wsp:Policy>\n" +
                        "</sp:TransportToken>\n" +
                        "   <sp:AlgorithmSuite>\n" +
                        "       <wsp:Policy>\n" +
                        "           <sp:Basic256/>\n" +
                        "       </wsp:Policy>\n" +
                        "   </sp:AlgorithmSuite>\n" +
                        "</wsp:Policy>\n" +
                        "</sp:TransportBinding>";

        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);
        HttpsTokenSecurityEvent httpsTokenSecurityEvent = new HttpsTokenSecurityEvent();
        HttpsSecurityTokenImpl securityToken = getHttpsSecurityToken(WSSecurityTokenConstants.X509V3Token);
        securityToken.addTokenUsage(WSSecurityTokenConstants.TokenUsage_MainEncryption);
        httpsTokenSecurityEvent.setSecurityToken(securityToken);
        httpsTokenSecurityEvent.setAuthenticationType(HttpsTokenSecurityEvent.AuthenticationType.HttpsClientCertificateAuthentication);
        httpsTokenSecurityEvent.setIssuerName("xs:anyURI");
        policyEnforcer.registerSecurityEvent(httpsTokenSecurityEvent);

        OperationSecurityEvent operationSecurityEvent = new OperationSecurityEvent();
        operationSecurityEvent.setOperation(new QName("definitions"));
        policyEnforcer.registerSecurityEvent(operationSecurityEvent);

        policyEnforcer.doFinal();
    }

    @Test
    public void testPolicyNegative() throws Exception {
        String policyString =
                "<sp:TransportBinding xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\" xmlns:sp3=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200802\">\n" +
                        "<wsp:Policy xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">\n" +
                        "<sp:TransportToken>\n" +
                        "   <wsp:Policy>\n" +
                        "       <sp:HttpsToken>\n" +
                        "       <sp:IssuerName>xs:anyURI</sp:IssuerName>\n" +
                        "       <wsp:Policy xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">\n" +
                        "           <sp:RequireClientCertificate/>\n" +
                        "       </wsp:Policy>\n" +
                        "       </sp:HttpsToken>" +
                        "   </wsp:Policy>\n" +
                        "</sp:TransportToken>\n" +
                        "   <sp:AlgorithmSuite>\n" +
                        "       <wsp:Policy>\n" +
                        "           <sp:Basic256/>\n" +
                        "       </wsp:Policy>\n" +
                        "   </sp:AlgorithmSuite>\n" +
                        "</wsp:Policy>\n" +
                        "</sp:TransportBinding>";

        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);
        HttpsTokenSecurityEvent httpsTokenSecurityEvent = new HttpsTokenSecurityEvent();
        HttpsSecurityTokenImpl securityToken = getHttpsSecurityToken(WSSecurityTokenConstants.X509V3Token);
        securityToken.addTokenUsage(WSSecurityTokenConstants.TokenUsage_MainEncryption);
        httpsTokenSecurityEvent.setSecurityToken(securityToken);
        httpsTokenSecurityEvent.setAuthenticationType(HttpsTokenSecurityEvent.AuthenticationType.HttpBasicAuthentication);
        httpsTokenSecurityEvent.setIssuerName("xs:anyURI");
        policyEnforcer.registerSecurityEvent(httpsTokenSecurityEvent);

        OperationSecurityEvent operationSecurityEvent = new OperationSecurityEvent();
        operationSecurityEvent.setOperation(new QName("definitions"));
        try {
            policyEnforcer.registerSecurityEvent(operationSecurityEvent);
            Assert.fail("Exception expected");
        } catch (WSSecurityException e) {
            Assert.assertTrue(e.getCause() instanceof PolicyViolationException);
            Assert.assertEquals(e.getCause().getMessage(),
                    "Policy enforces HttpClientCertificateAuthentication but we got HttpBasicAuthentication");
            Assert.assertEquals(e.getFaultCode(), WSSecurityException.INVALID_SECURITY);
        }
    }
}
