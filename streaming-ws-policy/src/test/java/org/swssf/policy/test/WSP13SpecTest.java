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

import org.apache.ws.secpolicy.WSSPolicyException;
import org.swssf.policy.PolicyEnforcer;
import org.swssf.wss.securityEvent.SecurityEvent;
import org.swssf.wss.test.InboundWSSecurityContextImplTest;
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

    @DataProvider(name = "ignoreEventsTransportBinding")
    public Object[][] ignoreEventsTransportBinding() {
        return new Object[][]{
                {null, null, null},
                {SecurityEvent.Event.HttpsToken, 1, "Assertion {http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702}HttpsToken not satisfied"},
                {SecurityEvent.Event.RequiredElement, 3, "\nElement /{http://schemas.xmlsoap.org/soap/envelope/}Envelope/{http://schemas.xmlsoap.org/soap/envelope/}Header/{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd}Security/{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd}Timestamp must be present"},
                {SecurityEvent.Event.UsernameToken, 4, "Assertion {http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702}UsernameToken not satisfied"},
                {SecurityEvent.Event.X509Token, 5, "Assertion {http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702}X509Token not satisfied"},
        };
    }

    @Test(dataProvider = "ignoreEventsTransportBinding")
    public void testTransportBindingC11(SecurityEvent.Event ignoreEvent, Integer eventIndex, String expectedErrorMessage) throws Exception {
        String policyString = loadResourceAsString("testdata/policy/transportBindingPolicyC11.xml", "UTF-8");

        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);

        List<SecurityEvent> securityEventList = inboundWSSecurityContextImplTest.generateTransportBindingSecurityEvents();
        for (int i = 0; i < securityEventList.size(); i++) {
            SecurityEvent securityEvent = securityEventList.get(i);
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
        try {
            policyEnforcer.doFinal();
            if (ignoreEvent != null) {
                Assert.fail("Expected WSSPolicyException");
            }
        } catch (WSSPolicyException e) {
            if (ignoreEvent == null) {
                Assert.fail("Unexpected WSSPolicyException");
            }
            Assert.assertEquals(e.getMessage(), expectedErrorMessage);
        }
    }

    @DataProvider(name = "ignoreEventsAsymmetricBinding")
    public Object[][] ignoreEventsAsymmetricBinding() {
        return new Object[][]{
                {null, null, null},
                {SecurityEvent.Event.RequiredElement, 2, "\nElement /{http://schemas.xmlsoap.org/soap/envelope/}Envelope/{http://schemas.xmlsoap.org/soap/envelope/}Header/{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd}Security/{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd}Timestamp must be present"},
                {SecurityEvent.Event.X509Token, 3, "Assertion {http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702}X509Token not satisfied"},
                {SecurityEvent.Event.UsernameToken, 8, "Assertion {http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702}UsernameToken not satisfied"},
        };
    }

    @Test(dataProvider = "ignoreEventsAsymmetricBinding")
    public void testAsymmetricBindingC31(SecurityEvent.Event ignoreEvent, Integer eventIndex, String expectedErrorMessage) throws Exception {
        String policyString = loadResourceAsString("testdata/policy/asymmetricBindingPolicyC31.xml", "UTF-8");

        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);

        List<SecurityEvent> securityEventList = inboundWSSecurityContextImplTest.generateAsymmetricBindingSecurityEvents();
        for (int i = 0; i < securityEventList.size(); i++) {
            SecurityEvent securityEvent = securityEventList.get(i);
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
        try {
            policyEnforcer.doFinal();
            if (ignoreEvent != null) {
                Assert.fail("Expected WSSPolicyException");
            }
        } catch (WSSPolicyException e) {
            if (ignoreEvent == null) {
                Assert.fail("Unexpected WSSPolicyException");
            }
            Assert.assertEquals(e.getMessage(), expectedErrorMessage);
        }
    }

    @DataProvider(name = "ignoreEventsSymmetricBinding")
    public Object[][] ignoreEventsSymmetricBinding() {
        return new Object[][]{
                {null, null, null},
                {SecurityEvent.Event.RequiredElement, 2, "\nElement /{http://schemas.xmlsoap.org/soap/envelope/}Envelope/{http://schemas.xmlsoap.org/soap/envelope/}Header/{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd}Security/{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd}Timestamp must be present"},
                {SecurityEvent.Event.UsernameToken, 5, "Assertion {http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702}UsernameToken not satisfied"},
                {SecurityEvent.Event.X509Token, 16, "Assertion {http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702}X509Token not satisfied"},
        };
    }

    @Test(dataProvider = "ignoreEventsSymmetricBinding")
    public void testSymmetricBindingC31(SecurityEvent.Event ignoreEvent, Integer eventIndex, String expectedErrorMessage) throws Exception {
        String policyString = loadResourceAsString("testdata/policy/symmetricBindingPolicyC21.xml", "UTF-8");

        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);

        List<SecurityEvent> securityEventList = inboundWSSecurityContextImplTest.generateSymmetricBindingSecurityEvents();
        for (int i = 0; i < securityEventList.size(); i++) {
            SecurityEvent securityEvent = securityEventList.get(i);
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
        try {
            policyEnforcer.doFinal();
            if (ignoreEvent != null) {
                Assert.fail("Expected WSSPolicyException");
            }
        } catch (WSSPolicyException e) {
            if (ignoreEvent == null) {
                Assert.fail("Unexpected WSSPolicyException");
            }
            Assert.assertEquals(e.getMessage(), expectedErrorMessage);
        }
    }
}
