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
package org.apache.wss4j.policy.stax.assertionStates;

import javax.xml.namespace.QName;

import org.apache.wss4j.common.WSSPolicyException;
import org.apache.wss4j.policy.SP13Constants;
import org.apache.wss4j.policy.SPConstants;
import org.apache.wss4j.policy.model.AbstractSecurityAssertion;
import org.apache.wss4j.policy.model.AbstractToken;
import org.apache.wss4j.policy.model.UsernameToken;
import org.apache.wss4j.policy.stax.PolicyAsserter;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.securityToken.UsernameSecurityToken;
import org.apache.wss4j.stax.securityEvent.UsernameTokenSecurityEvent;
import org.apache.wss4j.stax.securityEvent.WSSecurityEventConstants;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.securityEvent.SecurityEventConstants;
import org.apache.xml.security.stax.securityEvent.TokenSecurityEvent;
import org.apache.xml.security.stax.securityToken.SecurityToken;

/**
 * WSP1.3, 5.4.1 UsernameToken Assertion
 */

public class UsernameTokenAssertionState extends TokenAssertionState {

    public UsernameTokenAssertionState(AbstractSecurityAssertion assertion, boolean asserted,
                                       PolicyAsserter policyAsserter, boolean initiator) {
        super(assertion, asserted, policyAsserter, initiator);

        if (asserted) {
            UsernameToken usernameToken = (UsernameToken) getAssertion();
            String namespace = usernameToken.getName().getNamespaceURI();
            if (usernameToken.getPasswordType() != null) {
                getPolicyAsserter().assertPolicy(new QName(namespace, usernameToken.getPasswordType().name()));
            }
            if (usernameToken.isCreated()) {
                getPolicyAsserter().assertPolicy(SP13Constants.CREATED);
            }

            if (usernameToken.isNonce()) {
                getPolicyAsserter().assertPolicy(SP13Constants.NONCE);
            }

            if (usernameToken.getUsernameTokenType() != null) {
                getPolicyAsserter().assertPolicy(new QName(namespace, usernameToken.getUsernameTokenType().name()));
            }
        }
    }

    @Override
    public SecurityEventConstants.Event[] getSecurityEventType() {
        return new SecurityEventConstants.Event[]{
                WSSecurityEventConstants.USERNAME_TOKEN
        };
    }

    @Override
    public boolean assertToken(TokenSecurityEvent<? extends SecurityToken> tokenSecurityEvent,
                               AbstractToken abstractToken) throws WSSPolicyException, XMLSecurityException {
        if (!(tokenSecurityEvent instanceof UsernameTokenSecurityEvent)) {
            throw new WSSPolicyException("Expected a UsernameSecurityTokenEvent but got " + tokenSecurityEvent.getClass().getName());
        }
        UsernameSecurityToken usernameSecurityToken = (UsernameSecurityToken) tokenSecurityEvent.getSecurityToken();
        UsernameTokenSecurityEvent usernameTokenSecurityEvent = (UsernameTokenSecurityEvent) tokenSecurityEvent;
        UsernameToken usernameToken = (UsernameToken) abstractToken;

        String namespace = getAssertion().getName().getNamespaceURI();
        if (usernameToken.getPasswordType() != null) {
            switch (usernameToken.getPasswordType()) {
                case NoPassword:
                    if (usernameTokenSecurityEvent.getUsernameTokenPasswordType()
                        != WSSConstants.UsernameTokenPasswordType.PASSWORD_NONE) {
                        setErrorMessage("UsernameToken contains a password but the policy prohibits it");
                        getPolicyAsserter().unassertPolicy(new QName(namespace, SPConstants.NO_PASSWORD),
                                                           getErrorMessage());
                        return false;
                    }
                    getPolicyAsserter().assertPolicy(new QName(namespace, SPConstants.NO_PASSWORD));
                    break;
                case HashPassword:
                    if (usernameTokenSecurityEvent.getUsernameTokenPasswordType()
                        != WSSConstants.UsernameTokenPasswordType.PASSWORD_DIGEST) {
                        setErrorMessage("UsernameToken does not contain a hashed password");
                        getPolicyAsserter().unassertPolicy(new QName(namespace, SPConstants.HASH_PASSWORD),
                                                           getErrorMessage());
                        return false;
                    }
                    getPolicyAsserter().assertPolicy(new QName(namespace, SPConstants.HASH_PASSWORD));
                    break;
            }
        } else if (usernameTokenSecurityEvent.getUsernameTokenPasswordType() == WSSConstants.UsernameTokenPasswordType.PASSWORD_NONE) {
            // We must have a password for the default case
            setErrorMessage("UsernameToken must contain a password");
            getPolicyAsserter().unassertPolicy(getAssertion(), getErrorMessage());
            return false;
        } else if (usernameTokenSecurityEvent.getUsernameTokenPasswordType() == WSSConstants.UsernameTokenPasswordType.PASSWORD_DIGEST) {
            // We must have a plaintext password for the default case
            setErrorMessage("UsernameToken password must not be hashed");
            getPolicyAsserter().unassertPolicy(getAssertion(), getErrorMessage());
            return false;
        }
        if (usernameToken.isCreated()) {
            if (usernameSecurityToken.getCreatedTime() == null
                || usernameTokenSecurityEvent.getUsernameTokenPasswordType() != WSSConstants.UsernameTokenPasswordType.PASSWORD_TEXT) {
                setErrorMessage("UsernameToken does not contain a created timestamp or password is not plain text");
                getPolicyAsserter().unassertPolicy(SP13Constants.CREATED, getErrorMessage());
                return false;
            } else {
                getPolicyAsserter().assertPolicy(SP13Constants.CREATED);
            }
        }

        if (usernameToken.isNonce()) {
            if (usernameSecurityToken.getNonce() == null
                || usernameTokenSecurityEvent.getUsernameTokenPasswordType() != WSSConstants.UsernameTokenPasswordType.PASSWORD_TEXT) {
                setErrorMessage("UsernameToken does not contain a nonce or password is not plain text");
                getPolicyAsserter().unassertPolicy(SP13Constants.NONCE, getErrorMessage());
                return false;
            } else {
                getPolicyAsserter().assertPolicy(SP13Constants.NONCE);
            }
        }

        if (usernameToken.getUsernameTokenType() != null) {
            switch (usernameToken.getUsernameTokenType()) {
                case WssUsernameToken10:
                    if (usernameTokenSecurityEvent.getUsernameTokenProfile() != null
                        && usernameTokenSecurityEvent.getUsernameTokenProfile().equals(WSSConstants.NS_USERNAMETOKEN_PROFILE11)) {
                        setErrorMessage("Policy enforces UsernameToken profile 1.0 but we got 1.1");
                        getPolicyAsserter().unassertPolicy(new QName(namespace, SPConstants.USERNAME_TOKEN10),
                                                           getErrorMessage());
                        return false;
                    }
                    getPolicyAsserter().assertPolicy(new QName(namespace, SPConstants.USERNAME_TOKEN10));
                    break;
                case WssUsernameToken11:
                    if (usernameTokenSecurityEvent.getUsernameTokenProfile() != null
                        && !usernameTokenSecurityEvent.getUsernameTokenProfile().equals(WSSConstants.NS_USERNAMETOKEN_PROFILE11)) {
                        setErrorMessage("Policy enforces UsernameToken profile 1.1 but we got 1.0");
                        getPolicyAsserter().unassertPolicy(new QName(namespace, SPConstants.USERNAME_TOKEN11),
                                                           getErrorMessage());
                        return false;
                    }
                    getPolicyAsserter().assertPolicy(new QName(namespace, SPConstants.USERNAME_TOKEN11));
                    break;
            }
        }
        //always return true to prevent false alarm in case additional tokens with the same usage
        //appears in the message but do not fulfill the policy and are also not needed to fulfil the policy.
        getPolicyAsserter().assertPolicy(getAssertion());
        return true;
    }
}
