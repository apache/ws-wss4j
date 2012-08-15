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
import org.swssf.policy.PolicyViolationException;
import org.swssf.wss.ext.WSSConstants;
import org.swssf.wss.ext.WSSecurityException;
import org.swssf.wss.securityEvent.HttpsTokenSecurityEvent;
import org.swssf.wss.securityEvent.OperationSecurityEvent;
import org.apache.xml.security.stax.ext.SecurityToken;
import org.testng.Assert;
import org.testng.annotations.Test;

import javax.xml.namespace.QName;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
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
        SecurityToken securityToken = getX509Token(WSSConstants.X509V3Token);
        securityToken.addTokenUsage(SecurityToken.TokenUsage.MainEncryption);
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
        SecurityToken securityToken = getX509Token(WSSConstants.X509V3Token);
        securityToken.addTokenUsage(SecurityToken.TokenUsage.MainEncryption);
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
            Assert.assertEquals(e.getCause().getMessage(), "\n" +
                    "Policy enforces HttClientCertificateAuthentication but we got HttpBasicAuthentication");
        }
    }
}
