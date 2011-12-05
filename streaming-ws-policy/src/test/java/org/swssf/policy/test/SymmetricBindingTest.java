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
import org.swssf.wss.ext.WSSConstants;
import org.swssf.wss.ext.WSSecurityException;
import org.swssf.wss.impl.securityToken.SecureConversationSecurityToken;
import org.swssf.wss.securityEvent.*;
import org.testng.Assert;
import org.testng.annotations.Test;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class SymmetricBindingTest extends AbstractPolicyTestBase {

    @Test
    public void testPolicy() throws Exception {
        String policyString =
                "<sp:SymmetricBinding xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\" xmlns:sp3=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200802\">\n" +
                        "<wsp:Policy xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">\n" +
                        "<sp:IncludeTimestamp/>\n" +
                        "<sp:EncryptBeforeSigning/>\n" +
                        "<sp:EncryptSignature/>\n" +
                        "<sp:ProtectTokens/>\n" +
                        "<sp:OnlySignEntireHeadersAndBody/>\n" +
                        "</wsp:Policy>\n" +
                        "</sp:SymmetricBinding>";
        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);
        TimestampSecurityEvent timestampSecurityEvent = new TimestampSecurityEvent(SecurityEvent.Event.Timestamp);
        policyEnforcer.registerSecurityEvent(timestampSecurityEvent);
        SecureConversationTokenSecurityEvent secureConversationTokenSecurityEvent = new SecureConversationTokenSecurityEvent(SecurityEvent.Event.SecureConversationToken);
        secureConversationTokenSecurityEvent.setSecurityToken(new SecureConversationSecurityToken(null, null, null, "1", null));
        secureConversationTokenSecurityEvent.setTokenUsage(TokenSecurityEvent.TokenUsage.Signature);
        policyEnforcer.registerSecurityEvent(secureConversationTokenSecurityEvent);
        secureConversationTokenSecurityEvent.setTokenUsage(TokenSecurityEvent.TokenUsage.Encryption);
        policyEnforcer.registerSecurityEvent(secureConversationTokenSecurityEvent);
        EncryptedElementSecurityEvent encryptedElementSecurityEvent = new EncryptedElementSecurityEvent(SecurityEvent.Event.EncryptedElement, true);
        encryptedElementSecurityEvent.setElement(WSSConstants.TAG_dsig_Signature);
        policyEnforcer.registerSecurityEvent(encryptedElementSecurityEvent);
        encryptedElementSecurityEvent = new EncryptedElementSecurityEvent(SecurityEvent.Event.EncryptedElement, true);
        encryptedElementSecurityEvent.setElement(WSSConstants.TAG_wsse11_SignatureConfirmation);
        policyEnforcer.registerSecurityEvent(encryptedElementSecurityEvent);
        SignedPartSecurityEvent signedPartSecurityEvent = new SignedPartSecurityEvent(SecurityEvent.Event.SignedPart, true);
        signedPartSecurityEvent.setElement(WSSConstants.TAG_soap12_Body);
        policyEnforcer.registerSecurityEvent(signedPartSecurityEvent);
        policyEnforcer.doFinal();
    }

    @Test
    public void testPolicyNotIncludeTimestamp() throws Exception {
        String policyString =
                "<sp:SymmetricBinding xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\" xmlns:sp3=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200802\">\n" +
                        "<wsp:Policy xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">\n" +
                        "<sp:EncryptBeforeSigning/>\n" +
                        "<sp:EncryptSignature/>\n" +
                        "<sp:ProtectTokens/>\n" +
                        "<sp:OnlySignEntireHeadersAndBody/>\n" +
                        "</wsp:Policy>\n" +
                        "</sp:SymmetricBinding>";
        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);
        SecureConversationTokenSecurityEvent secureConversationTokenSecurityEvent = new SecureConversationTokenSecurityEvent(SecurityEvent.Event.X509Token);
        secureConversationTokenSecurityEvent.setSecurityToken(new SecureConversationSecurityToken(null, null, null, "1", null));
        secureConversationTokenSecurityEvent.setTokenUsage(TokenSecurityEvent.TokenUsage.Signature);
        policyEnforcer.registerSecurityEvent(secureConversationTokenSecurityEvent);
        secureConversationTokenSecurityEvent.setTokenUsage(TokenSecurityEvent.TokenUsage.Encryption);
        policyEnforcer.registerSecurityEvent(secureConversationTokenSecurityEvent);
        TimestampSecurityEvent timestampSecurityEvent = new TimestampSecurityEvent(SecurityEvent.Event.Timestamp);
        try {
            policyEnforcer.registerSecurityEvent(timestampSecurityEvent);
            Assert.fail("Exception expected");
        } catch (WSSecurityException e) {
            Assert.assertTrue(e.getCause() instanceof PolicyViolationException);
        }
    }

    @Test
    public void testPolicyWrongProtectionOrder() throws Exception {
        String policyString =
                "<sp:SymmetricBinding xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\" xmlns:sp3=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200802\">\n" +
                        "<wsp:Policy xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">\n" +
                        "<sp:IncludeTimestamp/>\n" +
                        "<sp:EncryptBeforeSigning/>\n" +
                        "<sp:EncryptSignature/>\n" +
                        "<sp:ProtectTokens/>\n" +
                        "<sp:OnlySignEntireHeadersAndBody/>\n" +
                        "</wsp:Policy>\n" +
                        "</sp:SymmetricBinding>";
        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);
        SecureConversationTokenSecurityEvent secureConversationTokenSecurityEvent = new SecureConversationTokenSecurityEvent(SecurityEvent.Event.X509Token);
        secureConversationTokenSecurityEvent.setSecurityToken(new SecureConversationSecurityToken(null, null, null, "1", null));
        secureConversationTokenSecurityEvent.setTokenUsage(TokenSecurityEvent.TokenUsage.Encryption);
        try {
            policyEnforcer.registerSecurityEvent(secureConversationTokenSecurityEvent);
            Assert.fail("Exception expected");
        } catch (WSSecurityException e) {
            Assert.assertTrue(e.getCause() instanceof PolicyViolationException);
        }
    }

    @Test
    public void testPolicySignatureNotEncrypted() throws Exception {
        String policyString =
                "<sp:SymmetricBinding xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\" xmlns:sp3=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200802\">\n" +
                        "<wsp:Policy xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">\n" +
                        "<sp:IncludeTimestamp/>\n" +
                        "<sp:EncryptBeforeSigning/>\n" +
                        "<sp:EncryptSignature/>\n" +
                        "<sp:ProtectTokens/>\n" +
                        "<sp:OnlySignEntireHeadersAndBody/>\n" +
                        "</wsp:Policy>\n" +
                        "</sp:SymmetricBinding>";
        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);
        TimestampSecurityEvent timestampSecurityEvent = new TimestampSecurityEvent(SecurityEvent.Event.Timestamp);
        policyEnforcer.registerSecurityEvent(timestampSecurityEvent);
        SecureConversationTokenSecurityEvent secureConversationTokenSecurityEvent = new SecureConversationTokenSecurityEvent(SecurityEvent.Event.X509Token);
        secureConversationTokenSecurityEvent.setSecurityToken(new SecureConversationSecurityToken(null, null, null, "1", null));
        secureConversationTokenSecurityEvent.setTokenUsage(TokenSecurityEvent.TokenUsage.Signature);
        policyEnforcer.registerSecurityEvent(secureConversationTokenSecurityEvent);
        secureConversationTokenSecurityEvent.setTokenUsage(TokenSecurityEvent.TokenUsage.Encryption);
        policyEnforcer.registerSecurityEvent(secureConversationTokenSecurityEvent);
        EncryptedElementSecurityEvent encryptedElementSecurityEvent = new EncryptedElementSecurityEvent(SecurityEvent.Event.EncryptedElement, false);
        encryptedElementSecurityEvent.setElement(WSSConstants.TAG_dsig_Signature);
        try {
            policyEnforcer.registerSecurityEvent(encryptedElementSecurityEvent);
            Assert.fail("Exception expected");
        } catch (WSSecurityException e) {
            Assert.assertTrue(e.getCause() instanceof PolicyViolationException);
        }
    }

    @Test
    public void testPolicyNotWholeBodySigned() throws Exception {
        String policyString =
                "<sp:SymmetricBinding xmlns:sp=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702\" xmlns:sp3=\"http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200802\">\n" +
                        "<wsp:Policy xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">\n" +
                        "<sp:IncludeTimestamp/>\n" +
                        "<sp:EncryptBeforeSigning/>\n" +
                        "<sp:EncryptSignature/>\n" +
                        "<sp:ProtectTokens/>\n" +
                        "<sp:OnlySignEntireHeadersAndBody/>\n" +
                        "</wsp:Policy>\n" +
                        "</sp:SymmetricBinding>";
        PolicyEnforcer policyEnforcer = buildAndStartPolicyEngine(policyString);
        TimestampSecurityEvent timestampSecurityEvent = new TimestampSecurityEvent(SecurityEvent.Event.Timestamp);
        policyEnforcer.registerSecurityEvent(timestampSecurityEvent);
        SecureConversationTokenSecurityEvent secureConversationTokenSecurityEvent = new SecureConversationTokenSecurityEvent(SecurityEvent.Event.X509Token);
        secureConversationTokenSecurityEvent.setSecurityToken(new SecureConversationSecurityToken(null, null, null, "1", null));
        secureConversationTokenSecurityEvent.setTokenUsage(TokenSecurityEvent.TokenUsage.Signature);
        policyEnforcer.registerSecurityEvent(secureConversationTokenSecurityEvent);
        secureConversationTokenSecurityEvent.setTokenUsage(TokenSecurityEvent.TokenUsage.Encryption);
        policyEnforcer.registerSecurityEvent(secureConversationTokenSecurityEvent);
        EncryptedElementSecurityEvent encryptedElementSecurityEvent = new EncryptedElementSecurityEvent(SecurityEvent.Event.EncryptedElement, true);
        encryptedElementSecurityEvent.setElement(WSSConstants.TAG_dsig_Signature);
        policyEnforcer.registerSecurityEvent(encryptedElementSecurityEvent);
        encryptedElementSecurityEvent = new EncryptedElementSecurityEvent(SecurityEvent.Event.EncryptedElement, true);
        encryptedElementSecurityEvent.setElement(WSSConstants.TAG_wsse11_SignatureConfirmation);
        policyEnforcer.registerSecurityEvent(encryptedElementSecurityEvent);
        SignedPartSecurityEvent signedPartSecurityEvent = new SignedPartSecurityEvent(SecurityEvent.Event.SignedPart, false);
        signedPartSecurityEvent.setElement(WSSConstants.TAG_soap12_Body);
        try {
            policyEnforcer.registerSecurityEvent(signedPartSecurityEvent);
            Assert.fail("Exception expected");
        } catch (WSSecurityException e) {
            Assert.assertTrue(e.getCause() instanceof PolicyViolationException);
        }
    }
}
