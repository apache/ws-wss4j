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
import org.apache.wss4j.policy.stax.PolicyEnforcer;
import org.apache.wss4j.policy.stax.PolicyViolationException;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.securityEvent.OperationSecurityEvent;
import org.apache.wss4j.stax.securityEvent.SignedPartSecurityEvent;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.testng.Assert;
import org.testng.annotations.Test;

import javax.xml.namespace.QName;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class SignedPartsTest extends AbstractPolicyTestBase {

    @Test
    public void testPolicy() throws Exception {
        String policyString =
                "<sp:SignedParts xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\" xmlns:sp3=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200802\">\n" +
                        "<sp:Body/>\n" +
                        "<sp:Header Name=\"a\" Namespace=\"http://example.org\"/>\n" +
                        "<sp:Attachments>\n" +
                        "<sp3:ContentSignatureTransform/>\n" +
                        "<sp3:AttachmentCompleteSignatureTransform/>\n" +
                        "</sp:Attachments>\n" +
                        "</sp:SignedParts>";
        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);

        OperationSecurityEvent operationSecurityEvent = new OperationSecurityEvent();
        operationSecurityEvent.setOperation(new QName("definitions"));
        policyEnforcer.registerSecurityEvent(operationSecurityEvent);

        List<XMLSecurityConstants.ContentType> protectionOrder = new LinkedList<XMLSecurityConstants.ContentType>();
        protectionOrder.add(XMLSecurityConstants.ContentType.SIGNATURE);
        protectionOrder.add(XMLSecurityConstants.ContentType.ENCRYPTION);
        SignedPartSecurityEvent signedPartSecurityEvent = new SignedPartSecurityEvent(null, true, protectionOrder);
        signedPartSecurityEvent.setElementPath(WSSConstants.SOAP_11_BODY_PATH);
        policyEnforcer.registerSecurityEvent(signedPartSecurityEvent);
        List<QName> headerPath = new ArrayList<QName>();
        headerPath.addAll(WSSConstants.SOAP_11_HEADER_PATH);
        headerPath.add(new QName("http://example.org", "a"));
        signedPartSecurityEvent.setElementPath(headerPath);
        policyEnforcer.registerSecurityEvent(signedPartSecurityEvent);
        //additional signedParts are also allowed!
        headerPath = new ArrayList<QName>();
        headerPath.addAll(WSSConstants.SOAP_11_HEADER_PATH);
        headerPath.add(new QName("http://example.org", "b"));
        signedPartSecurityEvent.setElementPath(headerPath);
        policyEnforcer.registerSecurityEvent(signedPartSecurityEvent);
        policyEnforcer.doFinal();
    }

    @Test
    public void testPolicyMultipleAssertionEventsNegative() throws Exception {
        String policyString =
                "<sp:SignedParts xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\" xmlns:sp3=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200802\">\n" +
                        "<sp:Body/>\n" +
                        "<sp:Header Name=\"a\" Namespace=\"http://example.org\"/>\n" +
                        "<sp:Attachments>\n" +
                        "<sp3:ContentSignatureTransform/>\n" +
                        "<sp3:AttachmentCompleteSignatureTransform/>\n" +
                        "</sp:Attachments>\n" +
                        "</sp:SignedParts>";
        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);

        OperationSecurityEvent operationSecurityEvent = new OperationSecurityEvent();
        operationSecurityEvent.setOperation(new QName("definitions"));
        policyEnforcer.registerSecurityEvent(operationSecurityEvent);

        List<XMLSecurityConstants.ContentType> protectionOrder = new LinkedList<XMLSecurityConstants.ContentType>();
        protectionOrder.add(XMLSecurityConstants.ContentType.SIGNATURE);
        protectionOrder.add(XMLSecurityConstants.ContentType.ENCRYPTION);
        SignedPartSecurityEvent signedPartSecurityEvent = new SignedPartSecurityEvent(null, true, protectionOrder);
        signedPartSecurityEvent.setElementPath(WSSConstants.SOAP_11_BODY_PATH);
        policyEnforcer.registerSecurityEvent(signedPartSecurityEvent);
        signedPartSecurityEvent = new SignedPartSecurityEvent(null, false, null);
        List<QName> headerPath = new ArrayList<QName>();
        headerPath.addAll(WSSConstants.SOAP_11_HEADER_PATH);
        headerPath.add(new QName("http://example.org", "a"));
        signedPartSecurityEvent.setElementPath(headerPath);
        try {
            policyEnforcer.registerSecurityEvent(signedPartSecurityEvent);
            Assert.fail("Exception expected");
        } catch (WSSecurityException e) {
            Assert.assertTrue(e.getCause() instanceof PolicyViolationException);
            Assert.assertEquals(e.getCause().getMessage(),
                    "Element /{http://schemas.xmlsoap.org/soap/envelope/}Envelope/{http://schemas.xmlsoap.org/soap/envelope/}Header/{http://example.org}a must be signed");
            Assert.assertEquals(e.getFaultCode(), WSSecurityException.INVALID_SECURITY);
        }
    }

    @Test
    public void testPolicyAllHeaders() throws Exception {
        String policyString =
                "<sp:SignedParts xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\" xmlns:sp3=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200802\">\n" +
                        "</sp:SignedParts>";
        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);

        OperationSecurityEvent operationSecurityEvent = new OperationSecurityEvent();
        operationSecurityEvent.setOperation(new QName("definitions"));
        policyEnforcer.registerSecurityEvent(operationSecurityEvent);

        List<XMLSecurityConstants.ContentType> protectionOrder = new LinkedList<XMLSecurityConstants.ContentType>();
        protectionOrder.add(XMLSecurityConstants.ContentType.SIGNATURE);
        protectionOrder.add(XMLSecurityConstants.ContentType.ENCRYPTION);
        SignedPartSecurityEvent signedPartSecurityEvent = new SignedPartSecurityEvent(null, true, protectionOrder);
        signedPartSecurityEvent.setElementPath(WSSConstants.SOAP_11_BODY_PATH);
        policyEnforcer.registerSecurityEvent(signedPartSecurityEvent);
        List<QName> headerPath = new ArrayList<QName>();
        headerPath.addAll(WSSConstants.SOAP_11_HEADER_PATH);
        headerPath.add(new QName("http://example.org", "a"));
        signedPartSecurityEvent.setElementPath(headerPath);
        policyEnforcer.registerSecurityEvent(signedPartSecurityEvent);
        headerPath = new ArrayList<QName>();
        headerPath.addAll(WSSConstants.SOAP_11_HEADER_PATH);
        headerPath.add(new QName("http://example.org", "b"));
        signedPartSecurityEvent.setElementPath(headerPath);
        policyEnforcer.registerSecurityEvent(signedPartSecurityEvent);
        policyEnforcer.doFinal();
    }

    @Test
    public void testPolicyBodyNegative() throws Exception {
        String policyString =
                "<sp:SignedParts xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\" xmlns:sp3=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200802\">\n" +
                        "</sp:SignedParts>";
        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);

        OperationSecurityEvent operationSecurityEvent = new OperationSecurityEvent();
        operationSecurityEvent.setOperation(new QName("definitions"));
        policyEnforcer.registerSecurityEvent(operationSecurityEvent);

        SignedPartSecurityEvent signedPartSecurityEvent = new SignedPartSecurityEvent(null, false, null);
        signedPartSecurityEvent.setElementPath(WSSConstants.SOAP_11_BODY_PATH);
        try {
            policyEnforcer.registerSecurityEvent(signedPartSecurityEvent);
        } catch (WSSecurityException e) {
            Assert.assertTrue(e.getCause() instanceof PolicyViolationException);
            Assert.assertEquals(e.getCause().getMessage(),
                    "Element /{http://schemas.xmlsoap.org/soap/envelope/}Envelope/{http://schemas.xmlsoap.org/soap/envelope/}Body must be signed");
            Assert.assertEquals(e.getFaultCode(), WSSecurityException.INVALID_SECURITY);
        }
    }

    @Test
    public void testPolicyWildcardHeader() throws Exception {
        String policyString =
                "<sp:SignedParts xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\" xmlns:sp3=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200802\">\n" +
                        "<sp:Body/>\n" +
                        "<sp:Header Namespace=\"http://example.org\"/>\n" +
                        "<sp:Attachments>\n" +
                        "<sp3:ContentSignatureTransform/>\n" +
                        "<sp3:AttachmentCompleteSignatureTransform/>\n" +
                        "</sp:Attachments>\n" +
                        "</sp:SignedParts>";
        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);

        OperationSecurityEvent operationSecurityEvent = new OperationSecurityEvent();
        operationSecurityEvent.setOperation(new QName("definitions"));
        policyEnforcer.registerSecurityEvent(operationSecurityEvent);

        List<XMLSecurityConstants.ContentType> protectionOrder = new LinkedList<XMLSecurityConstants.ContentType>();
        protectionOrder.add(XMLSecurityConstants.ContentType.SIGNATURE);
        protectionOrder.add(XMLSecurityConstants.ContentType.ENCRYPTION);
        SignedPartSecurityEvent signedPartSecurityEvent = new SignedPartSecurityEvent(null, true, protectionOrder);
        signedPartSecurityEvent.setElementPath(WSSConstants.SOAP_11_BODY_PATH);
        policyEnforcer.registerSecurityEvent(signedPartSecurityEvent);
        List<QName> headerPath = new ArrayList<QName>();
        headerPath.addAll(WSSConstants.SOAP_11_HEADER_PATH);
        headerPath.add(new QName("http://example.org", "a"));
        signedPartSecurityEvent.setElementPath(headerPath);
        policyEnforcer.registerSecurityEvent(signedPartSecurityEvent);
        //additional signedParts are also allowed!
        headerPath = new ArrayList<QName>();
        headerPath.addAll(WSSConstants.SOAP_11_HEADER_PATH);
        headerPath.add(new QName("http://example.org", "b"));
        signedPartSecurityEvent.setElementPath(headerPath);
        policyEnforcer.registerSecurityEvent(signedPartSecurityEvent);
        policyEnforcer.doFinal();
    }

    @Test
    public void testPolicyWildcardHeaderNegative() throws Exception {
        String policyString =
                "<sp:SignedParts xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\" xmlns:sp3=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200802\">\n" +
                        "<sp:Body/>\n" +
                        "<sp:Header Namespace=\"http://example.org\"/>\n" +
                        "<sp:Attachments>\n" +
                        "<sp3:ContentSignatureTransform/>\n" +
                        "<sp3:AttachmentCompleteSignatureTransform/>\n" +
                        "</sp:Attachments>\n" +
                        "</sp:SignedParts>";
        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);

        OperationSecurityEvent operationSecurityEvent = new OperationSecurityEvent();
        operationSecurityEvent.setOperation(new QName("definitions"));
        policyEnforcer.registerSecurityEvent(operationSecurityEvent);

        List<XMLSecurityConstants.ContentType> protectionOrder = new LinkedList<XMLSecurityConstants.ContentType>();
        protectionOrder.add(XMLSecurityConstants.ContentType.SIGNATURE);
        protectionOrder.add(XMLSecurityConstants.ContentType.ENCRYPTION);
        SignedPartSecurityEvent signedPartSecurityEvent = new SignedPartSecurityEvent(null, true, protectionOrder);
        signedPartSecurityEvent.setElementPath(WSSConstants.SOAP_11_BODY_PATH);
        policyEnforcer.registerSecurityEvent(signedPartSecurityEvent);
        signedPartSecurityEvent = new SignedPartSecurityEvent(null, false, null);
        List<QName> headerPath = new ArrayList<QName>();
        headerPath.addAll(WSSConstants.SOAP_11_HEADER_PATH);
        headerPath.add(new QName("http://example.org", "a"));
        signedPartSecurityEvent.setElementPath(headerPath);
        try {
            policyEnforcer.registerSecurityEvent(signedPartSecurityEvent);
            Assert.fail("Exception expected");
        } catch (WSSecurityException e) {
            Assert.assertTrue(e.getCause() instanceof PolicyViolationException);
            Assert.assertEquals(e.getCause().getMessage(),
                    "Element /{http://schemas.xmlsoap.org/soap/envelope/}Envelope/{http://schemas.xmlsoap.org/soap/envelope/}Header/{http://example.org}a must be signed");
            Assert.assertEquals(e.getFaultCode(), WSSecurityException.INVALID_SECURITY);
        }
    }
}
