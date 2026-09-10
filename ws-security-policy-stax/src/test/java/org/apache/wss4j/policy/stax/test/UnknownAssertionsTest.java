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

import org.apache.wss4j.common.WSSPolicyException;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.policy.stax.enforcer.PolicyEnforcer;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.impl.securityToken.HttpsSecurityTokenImpl;
import org.apache.wss4j.stax.impl.securityToken.X509SecurityTokenImpl;
import org.apache.wss4j.stax.securityEvent.HttpsTokenSecurityEvent;
import org.apache.wss4j.stax.securityEvent.OperationSecurityEvent;
import org.apache.wss4j.stax.securityEvent.RequiredElementSecurityEvent;
import org.apache.wss4j.stax.securityEvent.SignedPartSecurityEvent;
import org.apache.wss4j.stax.securityEvent.TimestampSecurityEvent;
import org.apache.wss4j.stax.securityEvent.X509TokenSecurityEvent;
import org.apache.wss4j.stax.securityToken.WSSecurityTokenConstants;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.securityEvent.ContentEncryptedElementSecurityEvent;
import org.apache.xml.security.stax.securityEvent.EncryptedElementSecurityEvent;
import org.apache.xml.security.stax.securityToken.InboundSecurityToken;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * Tests for the handling of policy assertions which the PolicyEnforcer cannot enforce:
 * unknown assertions must be warned about (or rejected, when the
 * {@link PolicyEnforcer#FAIL_ON_UNSUPPORTED_ASSERTIONS_PROPERTY} system property is set),
 * while stock policies - whose nested leaves and container assertions are enforced via
 * the parent model's assertion states - must never be flagged.
 */
public class UnknownAssertionsTest extends AbstractPolicyTestBase {

    private static final String UNKNOWN_ASSERTION_POLICY =
            "<foo:UnknownAssertion xmlns:foo=\"http://www.example.org/custom-assertions\"/>";

    /**
     * A stock transport binding (nested AlgorithmSuite/Basic256 and IncludeTimestamp
     * leaves) must build and verify cleanly even with failOnUnsupportedAssertions
     * enabled - the nested leaves are consumed by the parent model's parser and are
     * not unknown.
     */
    @Test
    public void testStockTransportBindingPolicyWithFailOnUnsupportedAssertionsEnabled() throws Exception {
        String policyString =
                "<sp:TransportBinding xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\" xmlns:sp3=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200802\">\n" +
                        "<wsp:Policy xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">\n" +
                        "   <sp:AlgorithmSuite>\n" +
                        "       <wsp:Policy>\n" +
                        "           <sp:Basic256/>\n" +
                        "       </wsp:Policy>\n" +
                        "   </sp:AlgorithmSuite>\n" +
                        "<sp:IncludeTimestamp/>\n" +
                        "</wsp:Policy>\n" +
                        "</sp:TransportBinding>";
        System.setProperty(PolicyEnforcer.FAIL_ON_UNSUPPORTED_ASSERTIONS_PROPERTY, "true");
        try {
            PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);
            TimestampSecurityEvent timestampSecurityEvent = new TimestampSecurityEvent();
            policyEnforcer.registerSecurityEvent(timestampSecurityEvent);

            RequiredElementSecurityEvent requiredElementSecurityEvent = new RequiredElementSecurityEvent();
            List<QName> headerPath = new ArrayList<>();
            headerPath.addAll(WSSConstants.SOAP_11_WSSE_SECURITY_HEADER_PATH);
            headerPath.add(WSSConstants.TAG_WSU_TIMESTAMP);
            requiredElementSecurityEvent.setElementPath(headerPath);
            policyEnforcer.registerSecurityEvent(requiredElementSecurityEvent);

            HttpsTokenSecurityEvent httpsTokenSecurityEvent = new HttpsTokenSecurityEvent();
            HttpsSecurityTokenImpl httpsSecurityToken = new HttpsSecurityTokenImpl(true, "username");
            httpsSecurityToken.addTokenUsage(WSSecurityTokenConstants.TOKENUSAGE_MAIN_SIGNATURE);
            httpsTokenSecurityEvent.setSecurityToken(httpsSecurityToken);
            policyEnforcer.registerSecurityEvent(httpsTokenSecurityEvent);

            OperationSecurityEvent operationSecurityEvent = new OperationSecurityEvent();
            operationSecurityEvent.setOperation(WSDL_DEFINITIONS);
            policyEnforcer.registerSecurityEvent(operationSecurityEvent);

            List<XMLSecurityConstants.ContentType> protectionOrder = new LinkedList<>();
            protectionOrder.add(XMLSecurityConstants.ContentType.SIGNATURE);
            protectionOrder.add(XMLSecurityConstants.ContentType.ENCRYPTION);
            EncryptedElementSecurityEvent encryptedElementSecurityEvent =
                    new EncryptedElementSecurityEvent(null, true, protectionOrder);
            headerPath = new ArrayList<>();
            headerPath.addAll(WSSConstants.SOAP_11_WSSE_SECURITY_HEADER_PATH);
            headerPath.add(WSSConstants.TAG_dsig_Signature);
            encryptedElementSecurityEvent.setElementPath(headerPath);
            policyEnforcer.registerSecurityEvent(encryptedElementSecurityEvent);

            encryptedElementSecurityEvent = new EncryptedElementSecurityEvent(null, true, protectionOrder);
            headerPath = new ArrayList<>();
            headerPath.addAll(WSSConstants.SOAP_11_WSSE_SECURITY_HEADER_PATH);
            headerPath.add(WSSConstants.TAG_WSSE11_SIG_CONF);
            encryptedElementSecurityEvent.setElementPath(headerPath);
            policyEnforcer.registerSecurityEvent(encryptedElementSecurityEvent);

            SignedPartSecurityEvent signedPartSecurityEvent = new SignedPartSecurityEvent(null, true, protectionOrder);
            signedPartSecurityEvent.setElementPath(WSSConstants.SOAP_11_BODY_PATH);
            policyEnforcer.registerSecurityEvent(signedPartSecurityEvent);

            policyEnforcer.doFinal();
        } finally {
            System.clearProperty(PolicyEnforcer.FAIL_ON_UNSUPPORTED_ASSERTIONS_PROPERTY);
        }
    }

    /**
     * A stock asymmetric binding whose tokens are carried in InitiatorToken/RecipientToken
     * wrappers (with nested X509Token leaves such as sp:WssX509V3Token11) must build and
     * verify cleanly even with failOnUnsupportedAssertions enabled - the token wrappers
     * are recognized containers whose nested policies are enforced via the
     * PolicyContainingAssertion recursion.
     */
    @Test
    public void testAsymmetricBindingWithTokenWrappersAndFailOnUnsupportedAssertionsEnabled() throws Exception {
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
        System.setProperty(PolicyEnforcer.FAIL_ON_UNSUPPORTED_ASSERTIONS_PROPERTY, "true");
        try {
            PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);
            X509TokenSecurityEvent initiatorX509TokenSecurityEvent = new X509TokenSecurityEvent();
            X509SecurityTokenImpl securityToken = getX509Token(WSSecurityTokenConstants.X509V3Token);
            securityToken.addTokenUsage(WSSecurityTokenConstants.TOKENUSAGE_MAIN_SIGNATURE);
            initiatorX509TokenSecurityEvent.setSecurityToken(securityToken);
            policyEnforcer.registerSecurityEvent(initiatorX509TokenSecurityEvent);

            X509TokenSecurityEvent recipientX509TokenSecurityEvent = new X509TokenSecurityEvent();
            securityToken = getX509Token(WSSecurityTokenConstants.X509V3Token);
            securityToken.addTokenUsage(WSSecurityTokenConstants.TOKENUSAGE_MAIN_ENCRYPTION);
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
            operationSecurityEvent.setOperation(WSDL_DEFINITIONS);
            policyEnforcer.registerSecurityEvent(operationSecurityEvent);

            policyEnforcer.doFinal();
        } finally {
            System.clearProperty(PolicyEnforcer.FAIL_ON_UNSUPPORTED_ASSERTIONS_PROPERTY);
        }
    }

    /**
     * A genuinely unknown top-level assertion (no registered builder) is skipped with a
     * warning by default - the historical behaviour - so the policy still builds.
     */
    @Test
    public void testUnknownPrimitiveAssertionIsSkippedByDefault() throws Exception {
        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(UNKNOWN_ASSERTION_POLICY);
        OperationSecurityEvent operationSecurityEvent = new OperationSecurityEvent();
        operationSecurityEvent.setOperation(WSDL_DEFINITIONS);
        policyEnforcer.registerSecurityEvent(operationSecurityEvent);
        policyEnforcer.doFinal();
    }

    /**
     * The same unknown top-level assertion must fail the policy build when
     * failOnUnsupportedAssertions is enabled.
     */
    @Test
    public void testUnknownPrimitiveAssertionFailsWhenConfigured() throws Exception {
        System.setProperty(PolicyEnforcer.FAIL_ON_UNSUPPORTED_ASSERTIONS_PROPERTY, "true");
        try {
            PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(UNKNOWN_ASSERTION_POLICY);
            OperationSecurityEvent operationSecurityEvent = new OperationSecurityEvent();
            operationSecurityEvent.setOperation(WSDL_DEFINITIONS);
            try {
                policyEnforcer.registerSecurityEvent(operationSecurityEvent);
                fail("Exception expected");
            } catch (WSSecurityException e) {
                assertTrue(e.getCause() instanceof WSSPolicyException);
                assertTrue(e.getCause().getMessage().contains("UnknownAssertion"));
            }
        } finally {
            System.clearProperty(PolicyEnforcer.FAIL_ON_UNSUPPORTED_ASSERTIONS_PROPERTY);
        }
    }
}
