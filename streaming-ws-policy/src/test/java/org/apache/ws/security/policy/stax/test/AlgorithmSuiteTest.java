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

import org.apache.xml.security.stax.securityEvent.AlgorithmSuiteSecurityEvent;
import org.apache.ws.security.policy.stax.PolicyEnforcer;
import org.apache.ws.security.policy.stax.PolicyViolationException;
import org.apache.ws.security.wss.ext.WSSConstants;
import org.apache.ws.security.wss.ext.WSSecurityException;
import org.apache.ws.security.wss.securityEvent.OperationSecurityEvent;
import org.testng.Assert;
import org.testng.annotations.Test;

import javax.xml.namespace.QName;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
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
            Assert.assertEquals(e.getCause().getMessage(), "\n" +
                    "Digest algorithm http://www.w3.org/2001/04/xmlenc#sha256 does not meet policy");
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
            Assert.assertEquals(e.getCause().getMessage(), "\n" +
                    "Encryption algorithm http://www.w3.org/2001/04/xmlenc#aes128-cbc does not meet policy\n" +
                    "Symmetric encryption algorithm key length 128 does not meet policy");
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
            Assert.assertEquals(e.getCause().getMessage(), "\n" +
                    "Encryption algorithm http://www.w3.org/2001/04/xmlenc#aes128-cbc does not meet policy\n" +
                    "Symmetric encryption algorithm key length 128 does not meet policy");
        }
    }
}
