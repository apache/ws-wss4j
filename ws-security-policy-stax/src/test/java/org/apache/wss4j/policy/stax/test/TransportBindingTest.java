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
import org.apache.wss4j.policy.stax.PolicyViolationException;
import org.apache.wss4j.policy.stax.enforcer.PolicyEnforcer;
import org.apache.wss4j.api.stax.ext.WSSConstants;
import org.apache.wss4j.api.stax.securityToken.WSSecurityTokenConstants;
import org.apache.wss4j.stax.impl.securityToken.HttpsSecurityTokenImpl;
import org.apache.wss4j.api.stax.securityEvent.*;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.securityEvent.EncryptedElementSecurityEvent;
import org.junit.jupiter.api.Test;

import javax.xml.namespace.QName;

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class TransportBindingTest extends AbstractPolicyTestBase {

    @Test
    public void testPolicy() throws Exception {
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
        operationSecurityEvent.setOperation(new QName("definitions"));
        policyEnforcer.registerSecurityEvent(operationSecurityEvent);

        List<XMLSecurityConstants.ContentType> protectionOrder = new LinkedList<>();
        protectionOrder.add(XMLSecurityConstants.ContentType.SIGNATURE);
        protectionOrder.add(XMLSecurityConstants.ContentType.ENCRYPTION);
        EncryptedElementSecurityEvent encryptedElementSecurityEvent = new EncryptedElementSecurityEvent(null, true, protectionOrder);
        headerPath = new ArrayList<>();
        headerPath.addAll(WSSConstants.SOAP_11_WSSE_SECURITY_HEADER_PATH);
        headerPath.add(WSSConstants.TAG_dsig_Signature);
        requiredElementSecurityEvent.setElementPath(headerPath);
        policyEnforcer.registerSecurityEvent(encryptedElementSecurityEvent);

        encryptedElementSecurityEvent = new EncryptedElementSecurityEvent(null, true, protectionOrder);
        headerPath = new ArrayList<>();
        headerPath.addAll(WSSConstants.SOAP_11_WSSE_SECURITY_HEADER_PATH);
        headerPath.add(WSSConstants.TAG_WSSE11_SIG_CONF);
        requiredElementSecurityEvent.setElementPath(headerPath);
        policyEnforcer.registerSecurityEvent(encryptedElementSecurityEvent);

        SignedPartSecurityEvent signedPartSecurityEvent = new SignedPartSecurityEvent(null, true, protectionOrder);
        signedPartSecurityEvent.setElementPath(WSSConstants.SOAP_11_BODY_PATH);
        policyEnforcer.registerSecurityEvent(signedPartSecurityEvent);

        policyEnforcer.doFinal();
    }

    @Test
    public void testPolicyNotIncludeTimestamp() throws Exception {
        String policyString =
                "<sp:TransportBinding xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\" xmlns:sp3=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200802\">\n" +
                        "<wsp:Policy xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">\n" +
                        "   <sp:AlgorithmSuite>\n" +
                        "       <wsp:Policy>\n" +
                        "           <sp:Basic256/>\n" +
                        "       </wsp:Policy>\n" +
                        "   </sp:AlgorithmSuite>\n" +
                        "</wsp:Policy>\n" +
                        "</sp:TransportBinding>";
        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);

        HttpsTokenSecurityEvent httpsTokenSecurityEvent = new HttpsTokenSecurityEvent();
        HttpsSecurityTokenImpl httpsSecurityToken = new HttpsSecurityTokenImpl(true, "username");
        httpsSecurityToken.addTokenUsage(WSSecurityTokenConstants.TOKENUSAGE_MAIN_SIGNATURE);
        httpsTokenSecurityEvent.setSecurityToken(httpsSecurityToken);
        policyEnforcer.registerSecurityEvent(httpsTokenSecurityEvent);

        TimestampSecurityEvent timestampSecurityEvent = new TimestampSecurityEvent();
        policyEnforcer.registerSecurityEvent(timestampSecurityEvent);

        OperationSecurityEvent operationSecurityEvent = new OperationSecurityEvent();
        operationSecurityEvent.setOperation(new QName("definitions"));

        try {
            policyEnforcer.registerSecurityEvent(operationSecurityEvent);
            fail("Exception expected");
        } catch (WSSecurityException e) {
            assertTrue(e.getCause() instanceof PolicyViolationException);
            assertEquals(e.getCause().getMessage(),
                    "Timestamp must not be present");
            assertEquals(e.getFaultCode(), WSSecurityException.INVALID_SECURITY);
        }
    }

    @Test
    public void testPolicySignatureNotEncrypted() throws Exception {
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

        List<XMLSecurityConstants.ContentType> protectionOrder = new LinkedList<>();
        protectionOrder.add(XMLSecurityConstants.ContentType.SIGNATURE);
        protectionOrder.add(XMLSecurityConstants.ContentType.ENCRYPTION);
        EncryptedElementSecurityEvent encryptedElementSecurityEvent = new EncryptedElementSecurityEvent(null, false, protectionOrder);
        headerPath = new ArrayList<>();
        headerPath.addAll(WSSConstants.SOAP_11_WSSE_SECURITY_HEADER_PATH);
        headerPath.add(WSSConstants.TAG_dsig_Signature);
        encryptedElementSecurityEvent.setElementPath(headerPath);
        policyEnforcer.registerSecurityEvent(encryptedElementSecurityEvent);

        OperationSecurityEvent operationSecurityEvent = new OperationSecurityEvent();
        operationSecurityEvent.setOperation(new QName("definitions"));
        policyEnforcer.registerSecurityEvent(operationSecurityEvent);

        policyEnforcer.doFinal();
    }

    @Test
    public void testPolicyNotWholeBodySigned() throws Exception {
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

        List<XMLSecurityConstants.ContentType> protectionOrder = new LinkedList<>();
        protectionOrder.add(XMLSecurityConstants.ContentType.SIGNATURE);
        protectionOrder.add(XMLSecurityConstants.ContentType.ENCRYPTION);
        EncryptedElementSecurityEvent encryptedElementSecurityEvent = new EncryptedElementSecurityEvent(null, true, protectionOrder);
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

        OperationSecurityEvent operationSecurityEvent = new OperationSecurityEvent();
        operationSecurityEvent.setOperation(new QName("definitions"));
        policyEnforcer.registerSecurityEvent(operationSecurityEvent);

        SignedPartSecurityEvent signedPartSecurityEvent = new SignedPartSecurityEvent(null, false, protectionOrder);
        signedPartSecurityEvent.setElementPath(WSSConstants.SOAP_11_BODY_PATH);
        policyEnforcer.registerSecurityEvent(signedPartSecurityEvent);

        policyEnforcer.doFinal();
    }
}