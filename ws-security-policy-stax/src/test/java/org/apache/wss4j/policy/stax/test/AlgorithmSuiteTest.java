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

import org.apache.neethi.Assertion;
import org.apache.neethi.Policy;
import org.apache.neethi.builders.AssertionBuilder;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.policy.SPConstants;
import org.apache.wss4j.policy.builders.AlgorithmSuiteBuilder;
import org.apache.wss4j.policy.model.AbstractSecurityAssertion;
import org.apache.wss4j.policy.model.AlgorithmSuite;
import org.apache.wss4j.policy.stax.PolicyEnforcer;
import org.apache.wss4j.policy.stax.PolicyViolationException;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.securityEvent.OperationSecurityEvent;
import org.apache.xml.security.stax.securityEvent.AlgorithmSuiteSecurityEvent;
import org.testng.Assert;
import org.testng.annotations.Test;

import javax.xml.namespace.QName;

import org.w3c.dom.Element;

import java.util.ArrayList;
import java.util.List;

public class AlgorithmSuiteTest extends AbstractPolicyTestBase {

    @Test
    public void testAlgorithmSuitePolicy() throws Exception {
        String policyString =
                "<sp:AlgorithmSuite xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\">\n" +
                        "<wsp:Policy xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">\n" +
                        "<sp:TripleDesRsa15/>\n" +
                        "</wsp:Policy>\n" +
                        "</sp:AlgorithmSuite>";
        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);

        OperationSecurityEvent operationSecurityEvent = new OperationSecurityEvent();
        operationSecurityEvent.setOperation(new QName("definitions"));
        policyEnforcer.registerSecurityEvent(operationSecurityEvent);

        AlgorithmSuiteSecurityEvent algorithmSuiteSecurityEvent = new AlgorithmSuiteSecurityEvent();
        algorithmSuiteSecurityEvent.setAlgorithmURI("http://www.w3.org/2001/04/xmlenc#tripledes-cbc");
        algorithmSuiteSecurityEvent.setKeyLength(192);
        algorithmSuiteSecurityEvent.setKeyUsage(WSSConstants.Enc);
        policyEnforcer.registerSecurityEvent(algorithmSuiteSecurityEvent);
        policyEnforcer.doFinal();
    }

    @Test
    public void testAlgorithmSuitePolicyMultipleAssertionEventsNegative() throws Exception {
        String policyString =
                "<sp:AlgorithmSuite xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\">\n" +
                        "<wsp:Policy xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">\n" +
                        "<sp:TripleDesRsa15/>\n" +
                        "</wsp:Policy>\n" +
                        "</sp:AlgorithmSuite>";
        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);

        OperationSecurityEvent operationSecurityEvent = new OperationSecurityEvent();
        operationSecurityEvent.setOperation(new QName("definitions"));
        policyEnforcer.registerSecurityEvent(operationSecurityEvent);

        AlgorithmSuiteSecurityEvent algorithmSuiteSecurityEvent = new AlgorithmSuiteSecurityEvent();
        algorithmSuiteSecurityEvent.setAlgorithmURI("http://www.w3.org/2001/04/xmlenc#tripledes-cbc");
        algorithmSuiteSecurityEvent.setKeyLength(192);
        algorithmSuiteSecurityEvent.setKeyUsage(WSSConstants.Enc);
        policyEnforcer.registerSecurityEvent(algorithmSuiteSecurityEvent);
        algorithmSuiteSecurityEvent.setAlgorithmURI("http://www.w3.org/2001/04/xmlenc#sha256");
        algorithmSuiteSecurityEvent.setKeyUsage(WSSConstants.Dig);
        try {
            policyEnforcer.registerSecurityEvent(algorithmSuiteSecurityEvent);
            Assert.fail("Exception expected");
        } catch (WSSecurityException e) {
            Assert.assertTrue(e.getCause() instanceof PolicyViolationException);
            Assert.assertEquals(e.getCause().getMessage(),
                    "Digest algorithm http://www.w3.org/2001/04/xmlenc#sha256 does not meet policy");
            Assert.assertEquals(e.getFaultCode(), WSSecurityException.INVALID_SECURITY);
        }
    }

    @Test
    public void testAlgorithmSuitePolicyNegative() throws Exception {
        String policyString =
                "<sp:AlgorithmSuite xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\">\n" +
                        "<wsp:Policy xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">\n" +
                        "<sp:TripleDesRsa15/>\n" +
                        "</wsp:Policy>\n" +
                        "</sp:AlgorithmSuite>";
        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);

        OperationSecurityEvent operationSecurityEvent = new OperationSecurityEvent();
        operationSecurityEvent.setOperation(new QName("definitions"));
        policyEnforcer.registerSecurityEvent(operationSecurityEvent);

        AlgorithmSuiteSecurityEvent algorithmSuiteSecurityEvent = new AlgorithmSuiteSecurityEvent();
        algorithmSuiteSecurityEvent.setAlgorithmURI("http://www.w3.org/2001/04/xmlenc#aes128-cbc");
        algorithmSuiteSecurityEvent.setKeyLength(128);
        algorithmSuiteSecurityEvent.setKeyUsage(WSSConstants.Enc);
        try {
            policyEnforcer.registerSecurityEvent(algorithmSuiteSecurityEvent);
            Assert.fail("Exception expected");
        } catch (WSSecurityException e) {
            Assert.assertTrue(e.getCause() instanceof PolicyViolationException);
            Assert.assertEquals(e.getCause().getMessage(),
                    "Encryption algorithm http://www.w3.org/2001/04/xmlenc#aes128-cbc does not meet policy\n" +
                    "Symmetric encryption algorithm key length 128 does not meet policy");
            Assert.assertEquals(e.getFaultCode(), WSSecurityException.INVALID_SECURITY);
        }
    }

    @Test
    public void testAlgorithmSuitePolicyAlternatives() throws Exception {
        String policyString =
                "<sp:AlgorithmSuite xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\">\n" +
                        "<wsp:Policy xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">\n" +
                        "<wsp:ExactlyOne>\n" +
                        "<sp:Basic256/>\n" +
                        "<sp:TripleDesRsa15/>\n" +
                        "</wsp:ExactlyOne>\n" +
                        "</wsp:Policy>\n" +
                        "</sp:AlgorithmSuite>";
        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);

        OperationSecurityEvent operationSecurityEvent = new OperationSecurityEvent();
        operationSecurityEvent.setOperation(new QName("definitions"));
        policyEnforcer.registerSecurityEvent(operationSecurityEvent);

        AlgorithmSuiteSecurityEvent algorithmSuiteSecurityEvent = new AlgorithmSuiteSecurityEvent();
        algorithmSuiteSecurityEvent.setAlgorithmURI("http://www.w3.org/2001/04/xmlenc#tripledes-cbc");
        algorithmSuiteSecurityEvent.setKeyLength(192);
        algorithmSuiteSecurityEvent.setKeyUsage(WSSConstants.Enc);
        policyEnforcer.registerSecurityEvent(algorithmSuiteSecurityEvent);
        policyEnforcer.doFinal();
    }

    @Test
    public void testAlgorithmSuitePolicyAlternativesNegative() throws Exception {
        String policyString =
                "<sp:AlgorithmSuite xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\">\n" +
                        "<wsp:Policy xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">\n" +
                        "<wsp:ExactlyOne>\n" +
                        "<sp:Basic256/>\n" +
                        "<sp:TripleDesRsa15/>\n" +
                        "</wsp:ExactlyOne>\n" +
                        "</wsp:Policy>\n" +
                        "</sp:AlgorithmSuite>";
        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);

        OperationSecurityEvent operationSecurityEvent = new OperationSecurityEvent();
        operationSecurityEvent.setOperation(new QName("definitions"));
        policyEnforcer.registerSecurityEvent(operationSecurityEvent);

        AlgorithmSuiteSecurityEvent algorithmSuiteSecurityEvent = new AlgorithmSuiteSecurityEvent();
        algorithmSuiteSecurityEvent.setAlgorithmURI("http://www.w3.org/2001/04/xmlenc#aes128-cbc");
        algorithmSuiteSecurityEvent.setKeyLength(128);
        algorithmSuiteSecurityEvent.setKeyUsage(WSSConstants.Enc);
        try {
            policyEnforcer.registerSecurityEvent(algorithmSuiteSecurityEvent);
            Assert.fail("Exception expected");
        } catch (WSSecurityException e) {
            Assert.assertTrue(e.getCause() instanceof PolicyViolationException);
            Assert.assertEquals(e.getCause().getMessage(),
                    "Encryption algorithm http://www.w3.org/2001/04/xmlenc#aes128-cbc does not meet policy\n" +
                    "Symmetric encryption algorithm key length 128 does not meet policy");
            Assert.assertEquals(e.getFaultCode(), WSSecurityException.INVALID_SECURITY);
        }
    }

    @Test
    public void testAES256GCMAlgorithmSuitePolicy() throws Exception {
        String policyString =
                "<sp:AlgorithmSuite xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\">\n" +
                        "<wsp:Policy xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">\n" +
                        "<cxf:Basic256GCM xmlns:cxf=\"http://cxf.apache.org/custom/security-policy\"/>\n" +
                        "</wsp:Policy>\n" +
                        "</sp:AlgorithmSuite>";

        class GCMAlgorithmSuite extends AlgorithmSuite {

            GCMAlgorithmSuite(SPConstants.SPVersion version, Policy nestedPolicy) {
                super(version, nestedPolicy);
            }

            @Override
            protected AbstractSecurityAssertion cloneAssertion(Policy nestedPolicy) {
                return new GCMAlgorithmSuite(getVersion(), nestedPolicy);
            }

            @Override
            protected void parseCustomAssertion(Assertion assertion) {
                String assertionName = assertion.getName().getLocalPart();
                String assertionNamespace = assertion.getName().getNamespaceURI();
                if (!"http://cxf.apache.org/custom/security-policy".equals(assertionNamespace)) {
                    return;
                }

                if ("Basic128GCM".equals(assertionName)) {
                    setAlgorithmSuiteType(new AlgorithmSuiteType(
                            "Basic128GCM",
                            SPConstants.SHA1,
                            WSSConstants.NS_XENC11_AES128_GCM,
                            SPConstants.KW_AES128,
                            SPConstants.KW_RSA_OAEP,
                            SPConstants.P_SHA1_L128,
                            SPConstants.P_SHA1_L128,
                            128, 128, 128, 256, 1024, 4096
                    ));
                } else if ("Basic192GCM".equals(assertionName)) {
                    setAlgorithmSuiteType(new AlgorithmSuiteType(
                            "Basic192GCM",
                            SPConstants.SHA1,
                            WSSConstants.NS_XENC11_AES192_GCM,
                            SPConstants.KW_AES192,
                            SPConstants.KW_RSA_OAEP,
                            SPConstants.P_SHA1_L192,
                            SPConstants.P_SHA1_L192,
                            192, 192, 192, 256, 1024, 4096));
                } else if ("Basic256GCM".equals(assertionName)) {
                    setAlgorithmSuiteType(new AlgorithmSuiteType(
                            "Basic256GCM",
                            SPConstants.SHA1,
                            WSSConstants.NS_XENC11_AES256_GCM,
                            SPConstants.KW_AES256,
                            SPConstants.KW_RSA_OAEP,
                            SPConstants.P_SHA1_L256,
                            SPConstants.P_SHA1_L192,
                            256, 192, 256, 256, 1024, 4096));
                }
            }
        }

        class GCMAlgorithmSuiteBuilder extends AlgorithmSuiteBuilder {
            @Override
            protected AlgorithmSuite createAlgorithmSuite(SPConstants.SPVersion version, Policy nestedPolicy) {
                return new GCMAlgorithmSuite(version, nestedPolicy);
            }
        }

        List<AssertionBuilder<Element>> customAssertionBuilders = new ArrayList<AssertionBuilder<Element>>();
        customAssertionBuilders.add(new GCMAlgorithmSuiteBuilder());
        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString, false, customAssertionBuilders);

        OperationSecurityEvent operationSecurityEvent = new OperationSecurityEvent();
        operationSecurityEvent.setOperation(new QName("definitions"));
        policyEnforcer.registerSecurityEvent(operationSecurityEvent);

        AlgorithmSuiteSecurityEvent algorithmSuiteSecurityEvent = new AlgorithmSuiteSecurityEvent();
        algorithmSuiteSecurityEvent.setAlgorithmURI(WSSConstants.NS_XENC11_AES256_GCM);
        algorithmSuiteSecurityEvent.setKeyLength(256);
        algorithmSuiteSecurityEvent.setKeyUsage(WSSConstants.Enc);
        policyEnforcer.registerSecurityEvent(algorithmSuiteSecurityEvent);

        algorithmSuiteSecurityEvent = new AlgorithmSuiteSecurityEvent();
        algorithmSuiteSecurityEvent.setAlgorithmURI(WSSConstants.NS_XENC_AES256);
        algorithmSuiteSecurityEvent.setKeyLength(256);
        algorithmSuiteSecurityEvent.setKeyUsage(WSSConstants.Enc);

        try {
            policyEnforcer.registerSecurityEvent(algorithmSuiteSecurityEvent);
            Assert.fail("Exception expected");
        } catch (Exception e) {
            Assert.assertEquals(e.getCause().getMessage(), "Encryption algorithm http://www.w3.org/2001/04/xmlenc#aes256-cbc does not meet policy");
        }
    }
}
