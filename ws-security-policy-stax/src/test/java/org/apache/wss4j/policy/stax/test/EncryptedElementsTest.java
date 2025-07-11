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

import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.policy.stax.PolicyViolationException;
import org.apache.wss4j.policy.stax.enforcer.PolicyEnforcer;
import org.apache.wss4j.api.stax.ext.WSSConstants;
import org.apache.wss4j.api.stax.securityEvent.OperationSecurityEvent;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.securityEvent.EncryptedElementSecurityEvent;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class EncryptedElementsTest extends AbstractPolicyTestBase {

    @Test
    public void testPolicy() throws Exception {
        String policyString =
                "<sp:EncryptedElements xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\" xmlns:sp3=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200802\">\n" +
                        "<sp:XPath xmlns:b=\"http://example.org\">/b:a</sp:XPath>\n" +
                        "</sp:EncryptedElements>";
        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);

        OperationSecurityEvent operationSecurityEvent = new OperationSecurityEvent();
        operationSecurityEvent.setOperation(new QName("definitions"));
        policyEnforcer.registerSecurityEvent(operationSecurityEvent);

        List<XMLSecurityConstants.ContentType> protectionOrder = new LinkedList<>();
        protectionOrder.add(XMLSecurityConstants.ContentType.SIGNATURE);
        protectionOrder.add(XMLSecurityConstants.ContentType.ENCRYPTION);
        EncryptedElementSecurityEvent encryptedElementSecurityEvent = new EncryptedElementSecurityEvent(null, true, protectionOrder);
        encryptedElementSecurityEvent.setElementPath(WSSConstants.SOAP_11_BODY_PATH);
        policyEnforcer.registerSecurityEvent(encryptedElementSecurityEvent);
        List<QName> headerPath = new ArrayList<>();
        headerPath.add(new QName("http://example.org", "a"));
        encryptedElementSecurityEvent.setElementPath(headerPath);
        policyEnforcer.registerSecurityEvent(encryptedElementSecurityEvent);
        //additional EncryptedElements are also allowed!
        headerPath = new ArrayList<>();
        headerPath.add(new QName("http://example.org", "b"));
        encryptedElementSecurityEvent.setElementPath(headerPath);
        policyEnforcer.registerSecurityEvent(encryptedElementSecurityEvent);
        policyEnforcer.doFinal();
    }

    @Test
    public void testPolicyMultipleAssertionEventsNegative() throws Exception {
        String policyString =
                "<sp:EncryptedElements xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\" xmlns:sp3=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200802\">\n" +
                        "<sp:XPath xmlns:b=\"http://example.org\">/b:a</sp:XPath>\n" +
                        "</sp:EncryptedElements>";
        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);

        OperationSecurityEvent operationSecurityEvent = new OperationSecurityEvent();
        operationSecurityEvent.setOperation(new QName("definitions"));
        policyEnforcer.registerSecurityEvent(operationSecurityEvent);

        List<XMLSecurityConstants.ContentType> protectionOrder = new LinkedList<>();
        protectionOrder.add(XMLSecurityConstants.ContentType.SIGNATURE);
        protectionOrder.add(XMLSecurityConstants.ContentType.ENCRYPTION);
        EncryptedElementSecurityEvent encryptedElementSecurityEvent = new EncryptedElementSecurityEvent(null, true, protectionOrder);
        encryptedElementSecurityEvent.setElementPath(WSSConstants.SOAP_11_BODY_PATH);
        policyEnforcer.registerSecurityEvent(encryptedElementSecurityEvent);
        encryptedElementSecurityEvent = new EncryptedElementSecurityEvent(null, false, null);
        List<QName> headerPath = new ArrayList<>();
        headerPath.add(new QName("http://example.org", "a"));
        encryptedElementSecurityEvent.setElementPath(headerPath);
        try {
            policyEnforcer.registerSecurityEvent(encryptedElementSecurityEvent);
            fail("Exception expected");
        } catch (WSSecurityException e) {
            assertTrue(e.getCause() instanceof PolicyViolationException);
            assertEquals(e.getCause().getMessage(),
                    "Element /{http://example.org}a must be encrypted");
            assertEquals(e.getFaultCode(), WSSecurityException.INVALID_SECURITY);
        }
    }
}