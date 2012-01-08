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
import org.swssf.wss.ext.WSSecurityException;
import org.swssf.wss.securityEvent.EncryptedPartSecurityEvent;
import org.swssf.wss.securityEvent.OperationSecurityEvent;
import org.testng.Assert;
import org.testng.annotations.Test;

import javax.xml.namespace.QName;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class EncryptedPartsTest extends AbstractPolicyTestBase {

    @Test
    public void testPolicy() throws Exception {
        String policyString =
                "<sp:EncryptedParts xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\" xmlns:sp3=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200802\">\n" +
                        "<sp:Body/>\n" +
                        "<sp:Header Name=\"a\" Namespace=\"http://example.org\"/>\n" +
                        "<sp:Attachments/>\n" +
                        "</sp:EncryptedParts>";
        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);

        OperationSecurityEvent operationSecurityEvent = new OperationSecurityEvent();
        operationSecurityEvent.setOperation(new QName("definitions"));
        policyEnforcer.registerSecurityEvent(operationSecurityEvent);

        EncryptedPartSecurityEvent encryptedPartSecurityEvent = new EncryptedPartSecurityEvent(null, true, false);
        encryptedPartSecurityEvent.setElement(new QName("http://schemas.xmlsoap.org/soap/envelope/", "Body"));
        policyEnforcer.registerSecurityEvent(encryptedPartSecurityEvent);
        encryptedPartSecurityEvent.setElement(new QName("http://example.org", "a"));
        policyEnforcer.registerSecurityEvent(encryptedPartSecurityEvent);
        //additional encryptedParts are also allowed!
        encryptedPartSecurityEvent.setElement(new QName("http://example.com", "b"));
        policyEnforcer.registerSecurityEvent(encryptedPartSecurityEvent);
        policyEnforcer.doFinal();
    }

    @Test
    public void testPolicyMultipleAssertionEventsNegative() throws Exception {
        String policyString =
                "<sp:EncryptedParts xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\" xmlns:sp3=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200802\">\n" +
                        "<sp:Body/>\n" +
                        "<sp:Header Name=\"a\" Namespace=\"http://example.org\"/>\n" +
                        "<sp:Attachments/>\n" +
                        "</sp:EncryptedParts>";
        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);

        OperationSecurityEvent operationSecurityEvent = new OperationSecurityEvent();
        operationSecurityEvent.setOperation(new QName("definitions"));
        policyEnforcer.registerSecurityEvent(operationSecurityEvent);

        EncryptedPartSecurityEvent encryptedPartSecurityEvent = new EncryptedPartSecurityEvent(null, true, false);
        encryptedPartSecurityEvent.setElement(new QName("http://schemas.xmlsoap.org/soap/envelope/", "Body"));
        policyEnforcer.registerSecurityEvent(encryptedPartSecurityEvent);
        encryptedPartSecurityEvent = new EncryptedPartSecurityEvent(null, false, false);
        encryptedPartSecurityEvent.setElement(new QName("http://example.org", "a"));
        try {
            policyEnforcer.registerSecurityEvent(encryptedPartSecurityEvent);
            Assert.fail("Exception expected");
        } catch (WSSecurityException e) {
            Assert.assertTrue(e.getCause() instanceof PolicyViolationException);
        }
    }

    @Test
    public void testPolicyWholeBody() throws Exception {
        String policyString =
                "<sp:EncryptedParts xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\" xmlns:sp3=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200802\">\n" +
                        "</sp:EncryptedParts>";
        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);

        OperationSecurityEvent operationSecurityEvent = new OperationSecurityEvent();
        operationSecurityEvent.setOperation(new QName("definitions"));
        policyEnforcer.registerSecurityEvent(operationSecurityEvent);

        EncryptedPartSecurityEvent encryptedPartSecurityEvent = new EncryptedPartSecurityEvent(null, true, false);
        encryptedPartSecurityEvent.setElement(new QName("http://schemas.xmlsoap.org/soap/envelope/", "Body"));
        policyEnforcer.registerSecurityEvent(encryptedPartSecurityEvent);
        encryptedPartSecurityEvent.setElement(new QName("http://example.org", "a"));
        policyEnforcer.registerSecurityEvent(encryptedPartSecurityEvent);
        encryptedPartSecurityEvent.setElement(new QName("http://example.com", "b"));
        policyEnforcer.registerSecurityEvent(encryptedPartSecurityEvent);
        policyEnforcer.doFinal();
    }

    @Test
    public void testPolicyWholeBodyNegative() throws Exception {
        String policyString =
                "<sp:EncryptedParts xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\" xmlns:sp3=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200802\">\n" +
                        "</sp:EncryptedParts>";
        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);

        OperationSecurityEvent operationSecurityEvent = new OperationSecurityEvent();
        operationSecurityEvent.setOperation(new QName("definitions"));
        policyEnforcer.registerSecurityEvent(operationSecurityEvent);

        EncryptedPartSecurityEvent encryptedPartSecurityEvent = new EncryptedPartSecurityEvent(null, false, false);
        encryptedPartSecurityEvent.setElement(new QName("http://schemas.xmlsoap.org/soap/envelope/", "Body"));
        try {
            policyEnforcer.registerSecurityEvent(encryptedPartSecurityEvent);
        } catch (WSSecurityException e) {
            Assert.assertTrue(e.getCause() instanceof PolicyViolationException);
        }
    }

    @Test
    public void testPolicyWildcardHeader() throws Exception {
        String policyString =
                "<sp:EncryptedParts xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\" xmlns:sp3=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200802\">\n" +
                        "<sp:Body/>\n" +
                        "<sp:Header Namespace=\"http://example.org\"/>\n" +
                        "<sp:Attachments/>\n" +
                        "</sp:EncryptedParts>";
        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);

        OperationSecurityEvent operationSecurityEvent = new OperationSecurityEvent();
        operationSecurityEvent.setOperation(new QName("definitions"));
        policyEnforcer.registerSecurityEvent(operationSecurityEvent);

        EncryptedPartSecurityEvent encryptedPartSecurityEvent = new EncryptedPartSecurityEvent(null, true, false);
        encryptedPartSecurityEvent.setElement(new QName("http://schemas.xmlsoap.org/soap/envelope/", "Body"));
        policyEnforcer.registerSecurityEvent(encryptedPartSecurityEvent);
        encryptedPartSecurityEvent.setElement(new QName("http://example.org", "a"));
        policyEnforcer.registerSecurityEvent(encryptedPartSecurityEvent);
        //additional encryptedParts are also allowed!
        encryptedPartSecurityEvent.setElement(new QName("http://example.com", "b"));
        policyEnforcer.registerSecurityEvent(encryptedPartSecurityEvent);
        policyEnforcer.doFinal();
    }

    @Test
    public void testPolicyWildcardHeaderNegative() throws Exception {
        String policyString =
                "<sp:EncryptedParts xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\" xmlns:sp3=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200802\">\n" +
                        "<sp:Body/>\n" +
                        "<sp:Header Namespace=\"http://example.org\"/>\n" +
                        "<sp:Attachments/>\n" +
                        "</sp:EncryptedParts>";
        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);

        OperationSecurityEvent operationSecurityEvent = new OperationSecurityEvent();
        operationSecurityEvent.setOperation(new QName("definitions"));
        policyEnforcer.registerSecurityEvent(operationSecurityEvent);

        EncryptedPartSecurityEvent encryptedPartSecurityEvent = new EncryptedPartSecurityEvent(null, true, false);
        encryptedPartSecurityEvent.setElement(new QName("http://schemas.xmlsoap.org/soap/envelope/", "Body"));
        policyEnforcer.registerSecurityEvent(encryptedPartSecurityEvent);
        encryptedPartSecurityEvent = new EncryptedPartSecurityEvent(null, false, false);
        encryptedPartSecurityEvent.setElement(new QName("http://example.org", "a"));
        try {
            policyEnforcer.registerSecurityEvent(encryptedPartSecurityEvent);
            Assert.fail("Exception expected");
        } catch (WSSecurityException e) {
            Assert.assertTrue(e.getCause() instanceof PolicyViolationException);
        }
    }
}
