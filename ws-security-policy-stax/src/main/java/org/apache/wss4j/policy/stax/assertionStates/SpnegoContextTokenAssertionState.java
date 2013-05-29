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

import org.apache.wss4j.policy.WSSPolicyException;
import org.apache.wss4j.policy.model.AbstractSecurityAssertion;
import org.apache.wss4j.policy.model.AbstractToken;
import org.apache.wss4j.policy.model.SpnegoContextToken;
import org.apache.xml.security.stax.securityEvent.SecurityEventConstants;
import org.apache.xml.security.stax.securityEvent.TokenSecurityEvent;
import org.apache.xml.security.stax.securityToken.SecurityToken;
import org.apache.wss4j.stax.securityEvent.SpnegoContextTokenSecurityEvent;
import org.apache.wss4j.stax.securityEvent.WSSecurityEventConstants;

/**
 * WSP1.3, 5.4.5 SpnegoContextToken Assertion
 */

public class SpnegoContextTokenAssertionState extends TokenAssertionState {

    public SpnegoContextTokenAssertionState(AbstractSecurityAssertion assertion, boolean asserted) {
        super(assertion, asserted);
    }

    @Override
    public SecurityEventConstants.Event[] getSecurityEventType() {
        return new SecurityEventConstants.Event[]{
                WSSecurityEventConstants.SpnegoContextToken
        };
    }

    @Override
    public boolean assertToken(TokenSecurityEvent<? extends SecurityToken> tokenSecurityEvent,
                               AbstractToken abstractToken) throws WSSPolicyException {
        if (!(tokenSecurityEvent instanceof SpnegoContextTokenSecurityEvent)) {
            throw new WSSPolicyException("Expected a SpnegoContextTokenSecurityEvent but got " + tokenSecurityEvent.getClass().getName());
        }

        SpnegoContextToken spnegoContextToken = (SpnegoContextToken) abstractToken;
        SpnegoContextTokenSecurityEvent spnegoContextTokenSecurityEvent = (SpnegoContextTokenSecurityEvent) tokenSecurityEvent;
        if ((spnegoContextToken.getIssuerName() != null)
            && !spnegoContextToken.getIssuerName().equals(spnegoContextTokenSecurityEvent.getIssuerName())) {
            setErrorMessage("IssuerName in Policy (" + spnegoContextToken.getIssuerName() + ") didn't match with the one in the IssuedToken (" + spnegoContextTokenSecurityEvent.getIssuerName() + ")");
            return false;
        }
        //todo MustNotSend* ?
        //always return true to prevent false alarm in case additional tokens with the same usage
        //appears in the message but do not fulfill the policy and are also not needed to fulfil the policy.
        return true;
    }
}
