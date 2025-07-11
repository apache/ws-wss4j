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
import org.apache.wss4j.policy.stax.enforcer.PolicyEnforcer;
import org.apache.wss4j.common.WSSPolicyException;
import org.apache.xml.security.stax.securityEvent.SecurityEvent;
import org.apache.xml.security.stax.securityEvent.SecurityEventConstants;
import org.apache.wss4j.api.stax.securityEvent.WSSecurityEventConstants;
import org.apache.wss4j.stax.test.InboundWSSecurityContextImplTest;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class WSP13SpecTest extends AbstractPolicyTestBase {

    private InboundWSSecurityContextImplTest inboundWSSecurityContextImplTest = new InboundWSSecurityContextImplTest();

    @Test
    public void testTransportBindingC11a() throws Exception {
        {
            String policyString = loadResourceAsString("testdata/policy/transportBindingPolicyC11.xml", StandardCharsets.UTF_8);

            PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);

            List<SecurityEvent> securityEventList = inboundWSSecurityContextImplTest.generateTransportBindingSecurityEvents();
            applyPolicy(null, null, null, policyEnforcer, securityEventList);
        }
        {
            String policyString = loadResourceAsString("testdata/policy/transportBindingPolicyC11.xml", StandardCharsets.UTF_8);

            PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);

            List<SecurityEvent> securityEventList = inboundWSSecurityContextImplTest.generateTransportBindingSecurityEvents();
            applyPolicy(WSSecurityEventConstants.HTTPS_TOKEN, 2, "Assertion {http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702}HttpsToken not satisfied", policyEnforcer, securityEventList);
        }
        {
            String policyString = loadResourceAsString("testdata/policy/transportBindingPolicyC11.xml", StandardCharsets.UTF_8);

            PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);

            List<SecurityEvent> securityEventList = inboundWSSecurityContextImplTest.generateTransportBindingSecurityEvents();
            applyPolicy(WSSecurityEventConstants.REQUIRED_ELEMENT, 4, "Element /{http://schemas.xmlsoap.org/soap/envelope/}Envelope/{http://schemas.xmlsoap.org/soap/envelope/}Header/{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd}Security/{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd}Timestamp must be present", policyEnforcer, securityEventList);
            }
        {
            String policyString = loadResourceAsString("testdata/policy/transportBindingPolicyC11.xml", StandardCharsets.UTF_8);

            PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);

            List<SecurityEvent> securityEventList = inboundWSSecurityContextImplTest.generateTransportBindingSecurityEvents();
            applyPolicy(WSSecurityEventConstants.USERNAME_TOKEN, 0, "Assertion {http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702}UsernameToken not satisfied", policyEnforcer, securityEventList);
        }
        {
            String policyString = loadResourceAsString("testdata/policy/transportBindingPolicyC11.xml", StandardCharsets.UTF_8);

            PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);

            List<SecurityEvent> securityEventList = inboundWSSecurityContextImplTest.generateTransportBindingSecurityEvents();
            applyPolicy(SecurityEventConstants.X509Token, 1, "Assertion {http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702}X509Token not satisfied", policyEnforcer, securityEventList);
        }
    }

    @Test
    public void testAsymmetricBindingC31a() throws Exception {
        {
            String policyString = loadResourceAsString("testdata/policy/asymmetricBindingPolicyC31.xml", StandardCharsets.UTF_8);

            PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);

            List<SecurityEvent> securityEventList = inboundWSSecurityContextImplTest.generateAsymmetricBindingSecurityEvents();
            applyPolicy(null, null, null, policyEnforcer, securityEventList);
        }
        {
            String policyString = loadResourceAsString("testdata/policy/asymmetricBindingPolicyC31.xml", StandardCharsets.UTF_8);

            PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);

            List<SecurityEvent> securityEventList = inboundWSSecurityContextImplTest.generateAsymmetricBindingSecurityEvents();
            applyPolicy(WSSecurityEventConstants.REQUIRED_ELEMENT, 8, "Element /{http://schemas.xmlsoap.org/soap/envelope/}Envelope/{http://schemas.xmlsoap.org/soap/envelope/}Header/{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd}Security/{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd}Timestamp must be present", policyEnforcer, securityEventList);
        }
        {
            String policyString = loadResourceAsString("testdata/policy/asymmetricBindingPolicyC31.xml", StandardCharsets.UTF_8);

            PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);

            List<SecurityEvent> securityEventList = inboundWSSecurityContextImplTest.generateAsymmetricBindingSecurityEvents();
            applyPolicy(SecurityEventConstants.X509Token, 0, "Assertion {http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702}X509Token not satisfied", policyEnforcer, securityEventList);
        }
        {
            String policyString = loadResourceAsString("testdata/policy/asymmetricBindingPolicyC31.xml", StandardCharsets.UTF_8);

            PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);

            List<SecurityEvent> securityEventList = inboundWSSecurityContextImplTest.generateAsymmetricBindingSecurityEvents();
            applyPolicy(WSSecurityEventConstants.USERNAME_TOKEN, 1, "Assertion {http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702}UsernameToken not satisfied", policyEnforcer, securityEventList);
        }
    }

    @Test
    public void testSymmetricBindingC21a() throws Exception {
        {
            String policyString = loadResourceAsString("testdata/policy/symmetricBindingPolicyC21a.xml", StandardCharsets.UTF_8);

            PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);

            List<SecurityEvent> securityEventList = inboundWSSecurityContextImplTest.generateSymmetricBindingSecurityEvents();
            applyPolicy(null, null, null, policyEnforcer, securityEventList);
        }
        {
            String policyString = loadResourceAsString("testdata/policy/symmetricBindingPolicyC21a.xml", StandardCharsets.UTF_8);

            PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);

            List<SecurityEvent> securityEventList = inboundWSSecurityContextImplTest.generateSymmetricBindingSecurityEvents();
            applyPolicy(WSSecurityEventConstants.REQUIRED_ELEMENT, 4, "Element /{http://schemas.xmlsoap.org/soap/envelope/}Envelope/{http://schemas.xmlsoap.org/soap/envelope/}Header/{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd}Security/{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd}Timestamp must be present", policyEnforcer, securityEventList);
        }
        {
            String policyString = loadResourceAsString("testdata/policy/symmetricBindingPolicyC21a.xml", StandardCharsets.UTF_8);

            PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);

            List<SecurityEvent> securityEventList = inboundWSSecurityContextImplTest.generateSymmetricBindingSecurityEvents();
            applyPolicy(WSSecurityEventConstants.SAML_TOKEN, -1, "Assertion {http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702}IssuedToken not satisfied", policyEnforcer, securityEventList);
        }
        {
            String policyString = loadResourceAsString("testdata/policy/symmetricBindingPolicyC21a.xml", StandardCharsets.UTF_8);

            PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);

            List<SecurityEvent> securityEventList = inboundWSSecurityContextImplTest.generateSymmetricBindingSecurityEvents();
            applyPolicy(WSSecurityEventConstants.USERNAME_TOKEN, 0, "Assertion {http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702}UsernameToken not satisfied", policyEnforcer, securityEventList);
        }
        {
            String policyString = loadResourceAsString("testdata/policy/symmetricBindingPolicyC21a.xml", StandardCharsets.UTF_8);

            PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);

            List<SecurityEvent> securityEventList = inboundWSSecurityContextImplTest.generateSymmetricBindingSecurityEvents();
            applyPolicy(SecurityEventConstants.X509Token, 2, "Assertion {http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702}X509Token not satisfied", policyEnforcer, securityEventList);
        }
    }

    @Test
    public void testSymmetricBindingC21b() throws Exception {
        {
            String policyString = loadResourceAsString("testdata/policy/symmetricBindingPolicyC21b.xml", StandardCharsets.UTF_8);

            PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);

            List<SecurityEvent> securityEventList = inboundWSSecurityContextImplTest.generateSymmetricBindingSecurityEvents();
            applyPolicy(null, null, null, policyEnforcer, securityEventList);
        }
        {
            String policyString = loadResourceAsString("testdata/policy/symmetricBindingPolicyC21b.xml", StandardCharsets.UTF_8);

            PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);

            List<SecurityEvent> securityEventList = inboundWSSecurityContextImplTest.generateSymmetricBindingSecurityEvents();
            applyPolicy(WSSecurityEventConstants.REQUIRED_ELEMENT, 4, "Element /{http://schemas.xmlsoap.org/soap/envelope/}Envelope/{http://schemas.xmlsoap.org/soap/envelope/}Header/{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd}Security/{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd}Timestamp must be present", policyEnforcer, securityEventList);
        }
        {
            String policyString = loadResourceAsString("testdata/policy/symmetricBindingPolicyC21b.xml", StandardCharsets.UTF_8);

            PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);

            List<SecurityEvent> securityEventList = inboundWSSecurityContextImplTest.generateSymmetricBindingSecurityEvents();
            applyPolicy(WSSecurityEventConstants.SAML_TOKEN, -1, "Assertion {http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702}IssuedToken not satisfied", policyEnforcer, securityEventList);
        }
        {
            String policyString = loadResourceAsString("testdata/policy/symmetricBindingPolicyC21b.xml", StandardCharsets.UTF_8);

            PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);

            List<SecurityEvent> securityEventList = inboundWSSecurityContextImplTest.generateSymmetricBindingSecurityEvents();
            applyPolicy(WSSecurityEventConstants.USERNAME_TOKEN, 0, "Assertion {http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702}UsernameToken not satisfied", policyEnforcer, securityEventList);
        }
        {
            String policyString = loadResourceAsString("testdata/policy/symmetricBindingPolicyC21b.xml", StandardCharsets.UTF_8);

            PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);

            List<SecurityEvent> securityEventList = inboundWSSecurityContextImplTest.generateSymmetricBindingSecurityEvents();
            applyPolicy(SecurityEventConstants.X509Token, 2, "Assertion {http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702}X509Token not satisfied", policyEnforcer, securityEventList);
        }
    }

    private void applyPolicy(SecurityEventConstants.Event ignoreEvent, Integer eventIndex, String expectedErrorMessage, PolicyEnforcer policyEnforcer, List<SecurityEvent> securityEventList) throws WSSecurityException {
        try {
            for (int i = 0; i < securityEventList.size(); i++) {
                SecurityEvent securityEvent = securityEventList.get(i);
                if (eventIndex != null && eventIndex == -1 && securityEvent.getSecurityEventType() == ignoreEvent) {
                    continue;
                }
                if (eventIndex != null && i == eventIndex && securityEvent.getSecurityEventType() != ignoreEvent) {
                    for (int j = 0; j < securityEventList.size(); j++) {
                        System.out.println(j + " " + securityEventList.get(j));
                    }
                    fail("Event at index " + eventIndex + " is not of type " + ignoreEvent);
                }
                if (ignoreEvent == null || i != eventIndex) {
                    policyEnforcer.registerSecurityEvent(securityEvent);
                }
            }

            policyEnforcer.doFinal();
            if (ignoreEvent != null) {
                fail("Expected WSSPolicyException");
            }
        } catch (WSSPolicyException e) {
            //Exception for policyEnforcer.doFinal();
            if (ignoreEvent == null) {
                fail("Unexpected WSSPolicyException: " + e.getMessage());
            }
            assertEquals(e.getMessage(), expectedErrorMessage);
        } catch (WSSecurityException e) {
            //Exception for policyEnforcer.registerSecurityEvent(securityEvent);
            if (ignoreEvent == null) {
                fail("Unexpected WSSPolicyException: " + e.getMessage());
            }
            assertTrue(e.getCause() instanceof WSSPolicyException);
            assertEquals(e.getCause().getMessage(), expectedErrorMessage);
        }
    }
}