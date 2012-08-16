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
package org.apache.ws.security.stax.policy.test;

import org.apache.ws.security.policy.WSSPolicyException;
import org.apache.xml.security.stax.securityEvent.SecurityEvent;
import org.apache.xml.security.stax.securityEvent.SecurityEventConstants;
import org.apache.ws.security.stax.policy.PolicyEnforcer;
import org.apache.ws.security.stax.wss.ext.WSSecurityException;
import org.apache.ws.security.stax.wss.securityEvent.WSSecurityEventConstants;
import org.apache.ws.security.stax.wss.test.InboundWSSecurityContextImplTest;
import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import java.util.List;

/**
 * @author $Author: $
 * @version $Revision: $ $Date: $
 */
public class WSP13SpecTest extends AbstractPolicyTestBase {

    private InboundWSSecurityContextImplTest inboundWSSecurityContextImplTest = new InboundWSSecurityContextImplTest();

    @DataProvider(name = "ignoreEventsTransportBindingC11a")
    public Object[][] ignoreEventsTransportBindingC11a() {
        return new Object[][]{
                {null, null, null},
                {WSSecurityEventConstants.HttpsToken, 0, "Assertion {http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702}HttpsToken not satisfied"},
                {WSSecurityEventConstants.RequiredElement, 2, "\nElement /{http://schemas.xmlsoap.org/soap/envelope/}Envelope/{http://schemas.xmlsoap.org/soap/envelope/}Header/{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd}Security/{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd}Timestamp must be present"},
                {WSSecurityEventConstants.UsernameToken, 3, "Assertion {http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702}UsernameToken not satisfied"},
                {SecurityEventConstants.X509Token, 4, "Assertion {http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702}X509Token not satisfied"},
        };
    }

    @Test(dataProvider = "ignoreEventsTransportBindingC11a")
    public void testTransportBindingC11a(SecurityEventConstants.Event ignoreEvent, Integer eventIndex, String expectedErrorMessage) throws Exception {
        String policyString = loadResourceAsString("testdata/policy/transportBindingPolicyC11.xml", "UTF-8");

        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);

        List<SecurityEvent> securityEventList = inboundWSSecurityContextImplTest.generateTransportBindingSecurityEvents();
        applyPolicy(ignoreEvent, eventIndex, expectedErrorMessage, policyEnforcer, securityEventList);
    }

    @DataProvider(name = "ignoreEventsAsymmetricBindingC31a")
    public Object[][] ignoreEventsAsymmetricBindingC31a() {
        return new Object[][]{
                {null, null, null},
                {WSSecurityEventConstants.RequiredElement, 1, "\nElement /{http://schemas.xmlsoap.org/soap/envelope/}Envelope/{http://schemas.xmlsoap.org/soap/envelope/}Header/{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd}Security/{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd}Timestamp must be present"},
                {SecurityEventConstants.X509Token, 2, "Assertion {http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702}X509Token not satisfied"},
                {WSSecurityEventConstants.UsernameToken, 7, "Assertion {http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702}UsernameToken not satisfied"},
        };
    }

    @Test(dataProvider = "ignoreEventsAsymmetricBindingC31a")
    public void testAsymmetricBindingC31a(SecurityEventConstants.Event ignoreEvent, Integer eventIndex, String expectedErrorMessage) throws Exception {
        String policyString = loadResourceAsString("testdata/policy/asymmetricBindingPolicyC31.xml", "UTF-8");

        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);

        List<SecurityEvent> securityEventList = inboundWSSecurityContextImplTest.generateAsymmetricBindingSecurityEvents();
        applyPolicy(ignoreEvent, eventIndex, expectedErrorMessage, policyEnforcer, securityEventList);
    }

    @DataProvider(name = "ignoreEventsSymmetricBindingC21a")
    public Object[][] ignoreEventsSymmetricBindingC21a() {
        return new Object[][]{
                {null, null, null},
                {WSSecurityEventConstants.RequiredElement, 1, "\nElement /{http://schemas.xmlsoap.org/soap/envelope/}Envelope/{http://schemas.xmlsoap.org/soap/envelope/}Header/{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd}Security/{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd}Timestamp must be present"},
                {WSSecurityEventConstants.SamlToken, -1, "Assertion {http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702}IssuedToken not satisfied"},
                {WSSecurityEventConstants.UsernameToken, 4, "Assertion {http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702}UsernameToken not satisfied"},
                {SecurityEventConstants.X509Token, 15, "Assertion {http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702}X509Token not satisfied"},
        };
    }

    @Test(dataProvider = "ignoreEventsSymmetricBindingC21a")
    public void testSymmetricBindingC21a(SecurityEventConstants.Event ignoreEvent, Integer eventIndex, String expectedErrorMessage) throws Exception {
        String policyString = loadResourceAsString("testdata/policy/symmetricBindingPolicyC21a.xml", "UTF-8");

        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);

        List<SecurityEvent> securityEventList = inboundWSSecurityContextImplTest.generateSymmetricBindingSecurityEvents();
        applyPolicy(ignoreEvent, eventIndex, expectedErrorMessage, policyEnforcer, securityEventList);
    }

    @DataProvider(name = "ignoreEventsSymmetricBindingC21b")
    public Object[][] ignoreEventsSymmetricBindingC21b() {
        return new Object[][]{
                {null, null, null},
                {WSSecurityEventConstants.RequiredElement, 1, "\nElement /{http://schemas.xmlsoap.org/soap/envelope/}Envelope/{http://schemas.xmlsoap.org/soap/envelope/}Header/{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd}Security/{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd}Timestamp must be present"},
                {WSSecurityEventConstants.SamlToken, -1, "Assertion {http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702}IssuedToken not satisfied"},
                {WSSecurityEventConstants.UsernameToken, 4, "Assertion {http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702}UsernameToken not satisfied"},
                {SecurityEventConstants.X509Token, 15, "Assertion {http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702}X509Token not satisfied"},
        };
    }

    @Test(dataProvider = "ignoreEventsSymmetricBindingC21b")
    public void testSymmetricBindingC21b(SecurityEventConstants.Event ignoreEvent, Integer eventIndex, String expectedErrorMessage) throws Exception {
        String policyString = loadResourceAsString("testdata/policy/symmetricBindingPolicyC21b.xml", "UTF-8");

        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);

        List<SecurityEvent> securityEventList = inboundWSSecurityContextImplTest.generateSymmetricBindingSecurityEvents();
        applyPolicy(ignoreEvent, eventIndex, expectedErrorMessage, policyEnforcer, securityEventList);
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
                    Assert.fail("Event at index " + eventIndex + " is not of type " + ignoreEvent);
                }
                if (ignoreEvent == null || i != eventIndex) {
                    policyEnforcer.registerSecurityEvent(securityEvent);
                }
            }

            policyEnforcer.doFinal();
            if (ignoreEvent != null) {
                Assert.fail("Expected WSSPolicyException");
            }
        } catch (WSSPolicyException e) {
            //Exception for policyEnforcer.doFinal();
            if (ignoreEvent == null) {
                Assert.fail("Unexpected WSSPolicyException");
            }
            Assert.assertEquals(e.getMessage(), expectedErrorMessage);
        } catch (WSSecurityException e) {
            //Exception for policyEnforcer.registerSecurityEvent(securityEvent);
            if (ignoreEvent == null) {
                Assert.fail("Unexpected WSSPolicyException");
            }
            Assert.assertTrue(e.getCause() instanceof WSSPolicyException);
            Assert.assertEquals(e.getCause().getMessage(), expectedErrorMessage);
        }
    }
}
