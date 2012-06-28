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
package org.swssf.policy.assertionStates;

import org.apache.ws.secpolicy.WSSPolicyException;
import org.apache.ws.secpolicy.model.AbstractSecurityAssertion;
import org.apache.ws.secpolicy.model.AbstractToken;
import org.apache.ws.secpolicy.model.UsernameToken;
import org.swssf.wss.ext.WSSConstants;
import org.swssf.wss.impl.securityToken.UsernameSecurityToken;
import org.swssf.wss.securityEvent.SecurityEvent;
import org.swssf.wss.securityEvent.TokenSecurityEvent;
import org.swssf.wss.securityEvent.UsernameTokenSecurityEvent;
import org.apache.xml.security.stax.ext.XMLSecurityException;

/**
 * WSP1.3, 5.4.1 UsernameToken Assertion
 *
 * @author $Author$
 * @version $Revision$ $Date$
 */

public class UsernameTokenAssertionState extends TokenAssertionState {

    public UsernameTokenAssertionState(AbstractSecurityAssertion assertion, boolean asserted) {
        super(assertion, asserted);
    }

    @Override
    public SecurityEvent.Event[] getSecurityEventType() {
        return new SecurityEvent.Event[]{
                SecurityEvent.Event.UsernameToken
        };
    }

    @Override
    public boolean assertToken(TokenSecurityEvent tokenSecurityEvent, AbstractToken abstractToken) throws WSSPolicyException, XMLSecurityException {
        if (!(tokenSecurityEvent instanceof UsernameTokenSecurityEvent)) {
            throw new WSSPolicyException("Expected a UsernameSecurityTokenEvent but got " + tokenSecurityEvent.getClass().getName());
        }
        UsernameSecurityToken usernameSecurityToken = (UsernameSecurityToken) tokenSecurityEvent.getSecurityToken();
        UsernameTokenSecurityEvent usernameTokenSecurityEvent = (UsernameTokenSecurityEvent) tokenSecurityEvent;
        UsernameToken usernameToken = (UsernameToken) abstractToken;

        if (usernameToken.getPasswordType() != null) {
            switch (usernameToken.getPasswordType()) {
                case NoPassword:
                    if (usernameTokenSecurityEvent.getUsernameTokenPasswordType() != WSSConstants.UsernameTokenPasswordType.PASSWORD_NONE) {
                        setErrorMessage("UsernameToken contains a password but the policy prohibits it");
                        return false;
                    }
                    break;
                case HashPassword:
                    if (usernameTokenSecurityEvent.getUsernameTokenPasswordType() != WSSConstants.UsernameTokenPasswordType.PASSWORD_DIGEST) {
                        setErrorMessage("UsernameToken does not contain a hashed password");
                        return false;
                    }
                    break;
            }
        }
        if (usernameToken.isCreated() && (usernameSecurityToken.getCreated() == null || usernameTokenSecurityEvent.getUsernameTokenPasswordType() != WSSConstants.UsernameTokenPasswordType.PASSWORD_TEXT)) {
            setErrorMessage("UsernameToken does not contain a created timestamp or password is not plain text");
            return false;
        }
        if (usernameToken.isNonce() && (usernameSecurityToken.getNonce() == null || usernameTokenSecurityEvent.getUsernameTokenPasswordType() != WSSConstants.UsernameTokenPasswordType.PASSWORD_TEXT)) {
            setErrorMessage("UsernameToken does not contain a nonce or password is not plain text");
            return false;
        }
        if (usernameToken.getUsernameTokenType() != null) {
            switch (usernameToken.getUsernameTokenType()) {
                case WssUsernameToken10:
                    if (usernameTokenSecurityEvent.getUsernameTokenProfile().equals(WSSConstants.NS_USERNAMETOKEN_PROFILE11)) {
                        setErrorMessage("Policy enforces UsernameToken profile 1.0 but we got 1.1");
                        return false;
                    }
                    break;
                case WssUsernameToken11:
                    if (!usernameTokenSecurityEvent.getUsernameTokenProfile().equals(WSSConstants.NS_USERNAMETOKEN_PROFILE11)) {
                        setErrorMessage("Policy enforces UsernameToken profile 1.1 but we got 1.0");
                        return false;
                    }
                    break;
            }
        }
        //always return true to prevent false alarm in case additional tokens with the same usage
        //appears in the message but do not fulfill the policy and are also not needed to fulfil the policy.
        return true;
    }
}
