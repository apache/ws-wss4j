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

import java.time.ZoneOffset;
import java.time.ZonedDateTime;

import javax.xml.namespace.QName;

import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.util.DateUtil;
import org.apache.wss4j.policy.stax.enforcer.PolicyEnforcer;
import org.apache.wss4j.policy.stax.enforcer.PolicyEnforcerFactory;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.impl.securityToken.UsernameSecurityTokenImpl;
import org.apache.wss4j.stax.securityEvent.OperationSecurityEvent;
import org.apache.wss4j.stax.securityEvent.UsernameTokenSecurityEvent;
import org.apache.wss4j.stax.securityToken.WSSecurityTokenConstants;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.impl.util.IDGenerator;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The engine's hardened defaults - rejecting password-less UsernameTokens and rsa-1_5 key
 * transport - are relaxed in policy mode so that the corresponding policy assertions can
 * take over. The relaxation belongs to the operation whose policy asks for it, not to every
 * operation of the endpoint.
 *
 * The WSDL behind these tests has two operations: one asks for sp:NoPassword, the other
 * names no UsernameToken at all, so nothing in its own policy would reject a password-less
 * token that the engine has already accepted.
 */
public class ScopedEngineDefaultsTest extends AbstractPolicyTestBase {

    private static final String NAMESPACE = "http://www.example.net/MixedPolicyService";
    private static final QName NO_PASSWORD_OPERATION = new QName(NAMESPACE, "noPasswordOperation");
    private static final QName PASSWORD_OPERATION = new QName(NAMESPACE, "passwordOperation");

    /**
     * Where SOAPAction has already selected the operation, only that operation's policy
     * decides. The operation that asks for no password gets the relaxation; the one that
     * does not, does not.
     */
    @Test
    public void testRelaxationIsScopedToTheOperationSelectedBySOAPAction() throws Exception {
        assertTrue(newPolicyEnforcer("noPasswordOperationAction").isUsernameTokenNoPasswordAllowedByPolicy());
        assertFalse(newPolicyEnforcer("passwordOperationAction").isUsernameTokenNoPasswordAllowedByPolicy());
    }

    /**
     * Without a SOAPAction the operation is not known while the security header is being
     * read, so the question can only be answered across every configured operation. The
     * engine default is still relaxed, as before, or a deployment whose operation cannot be
     * determined that early would stop working.
     */
    @Test
    public void testRelaxationStillGrantedWhenTheOperationIsNotYetKnown() throws Exception {
        assertTrue(newPolicyEnforcer("").isUsernameTokenNoPasswordAllowedByPolicy());
    }

    /**
     * ...but once the operation turns out to be the one whose policy says nothing about
     * UsernameTokens, a password-less token accepted under that relaxation is rejected.
     */
    @Test
    public void testPasswordlessTokenRejectedForAnOperationThatDoesNotAllowIt() throws Exception {
        PolicyEnforcer policyEnforcer = newPolicyEnforcer("");
        assertTrue(policyEnforcer.isUsernameTokenNoPasswordAllowedByPolicy());
        policyEnforcer.registerSecurityEvent(passwordlessUsernameTokenEvent());

        OperationSecurityEvent operationSecurityEvent = new OperationSecurityEvent();
        operationSecurityEvent.setOperation(PASSWORD_OPERATION);

        WSSecurityException ex = assertThrows(WSSecurityException.class,
                () -> policyEnforcer.registerSecurityEvent(operationSecurityEvent));

        assertEquals("The message uses a UsernameToken with no password, which the policy for "
                        + "operation " + PASSWORD_OPERATION + " does not allow",
                ex.getCause().getMessage());
        assertEquals(WSSecurityException.INVALID_SECURITY, ex.getFaultCode());
    }

    /**
     * The same message is accepted for the operation whose policy does ask for
     * sp:NoPassword.
     */
    @Test
    public void testPasswordlessTokenAcceptedForTheOperationThatAllowsIt() throws Exception {
        PolicyEnforcer policyEnforcer = newPolicyEnforcer("");
        assertTrue(policyEnforcer.isUsernameTokenNoPasswordAllowedByPolicy());
        policyEnforcer.registerSecurityEvent(passwordlessUsernameTokenEvent());

        OperationSecurityEvent operationSecurityEvent = new OperationSecurityEvent();
        operationSecurityEvent.setOperation(NO_PASSWORD_OPERATION);

        policyEnforcer.registerSecurityEvent(operationSecurityEvent);
    }

    /**
     * A message that carries no password-less token is unaffected, even though the
     * relaxation was granted across the endpoint.
     */
    @Test
    public void testOperationWithoutAPasswordlessTokenIsUnaffected() throws Exception {
        PolicyEnforcer policyEnforcer = newPolicyEnforcer("");
        assertTrue(policyEnforcer.isUsernameTokenNoPasswordAllowedByPolicy());

        OperationSecurityEvent operationSecurityEvent = new OperationSecurityEvent();
        operationSecurityEvent.setOperation(PASSWORD_OPERATION);

        policyEnforcer.registerSecurityEvent(operationSecurityEvent);
    }

    private PolicyEnforcer newPolicyEnforcer(String soapAction) throws Exception {
        PolicyEnforcerFactory policyEnforcerFactory = PolicyEnforcerFactory.newInstance(
                this.getClass().getClassLoader().getResource("testdata/wsdl/mixedPasswordPolicies.wsdl"));
        return policyEnforcerFactory.newPolicyEnforcer(soapAction, false, null, 0, false);
    }

    private UsernameTokenSecurityEvent passwordlessUsernameTokenEvent() throws XMLSecurityException {
        UsernameTokenSecurityEvent usernameTokenSecurityEvent = new UsernameTokenSecurityEvent();
        usernameTokenSecurityEvent.setUsernameTokenProfile(WSSConstants.NS_USERNAMETOKEN_PROFILE11);
        ZonedDateTime now = ZonedDateTime.now(ZoneOffset.UTC);
        String created = DateUtil.getDateTimeFormatter(true).format(now);
        UsernameSecurityTokenImpl usernameSecurityToken = new UsernameSecurityTokenImpl(
                WSSConstants.UsernameTokenPasswordType.PASSWORD_NONE,
                "username", null, created, null, new byte[10], 10L,
                null, IDGenerator.generateID(null),
                WSSecurityTokenConstants.KEYIDENTIFIER_SECURITY_TOKEN_DIRECT_REFERENCE);
        usernameSecurityToken.addTokenUsage(WSSecurityTokenConstants.TOKENUSAGE_SUPPORTING_TOKENS);
        usernameTokenSecurityEvent.setSecurityToken(usernameSecurityToken);
        return usernameTokenSecurityEvent;
    }
}
