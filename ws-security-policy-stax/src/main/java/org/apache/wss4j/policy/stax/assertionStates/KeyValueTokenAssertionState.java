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
import org.apache.wss4j.policy.SPConstants;
import org.apache.wss4j.policy.model.AbstractSecurityAssertion;
import org.apache.wss4j.policy.model.AbstractToken;
import org.apache.wss4j.policy.model.KeyValueToken;
import org.apache.wss4j.policy.stax.PolicyAsserter;
import org.apache.wss4j.stax.securityToken.RsaKeyValueSecurityToken;
import org.apache.wss4j.stax.securityEvent.KeyValueTokenSecurityEvent;
import org.apache.xml.security.stax.securityEvent.SecurityEventConstants;
import org.apache.xml.security.stax.securityEvent.TokenSecurityEvent;
import org.apache.xml.security.stax.securityToken.SecurityToken;
import org.apache.wss4j.stax.securityEvent.WSSecurityEventConstants;

/**
 * WSP1.3, 5.4.11 KeyValueToken Assertion
 */

public class KeyValueTokenAssertionState extends TokenAssertionState {

    public KeyValueTokenAssertionState(AbstractSecurityAssertion assertion, boolean asserted,
                                       PolicyAsserter policyAsserter, boolean initiator) {
        super(assertion, asserted, policyAsserter, initiator);

        if (asserted) {
            KeyValueToken token = (KeyValueToken) getAssertion();
            String namespace = token.getName().getNamespaceURI();
            if (token.isRsaKeyValue()) {
                getPolicyAsserter().assertPolicy(new QName(namespace, SPConstants.RSA_KEY_VALUE));
            }
        }
    }

    @Override
    public SecurityEventConstants.Event[] getSecurityEventType() {
        return new SecurityEventConstants.Event[]{
                WSSecurityEventConstants.KeyValueToken
        };
    }

    @Override
    public boolean assertToken(TokenSecurityEvent<? extends SecurityToken> tokenSecurityEvent,
                               AbstractToken abstractToken) throws WSSPolicyException {
        if (!(tokenSecurityEvent instanceof KeyValueTokenSecurityEvent)) {
            throw new WSSPolicyException("Expected a KeyValueTokenSecurityEvent but got " + tokenSecurityEvent.getClass().getName());
        }

        KeyValueTokenSecurityEvent keyValueTokenSecurityEvent = (KeyValueTokenSecurityEvent) tokenSecurityEvent;
        KeyValueToken keyValueToken = (KeyValueToken) abstractToken;

        String namespace = getAssertion().getName().getNamespaceURI();
        if (keyValueToken.isRsaKeyValue()) {
            if (!(keyValueTokenSecurityEvent.getSecurityToken() instanceof RsaKeyValueSecurityToken)) {
                setErrorMessage("Policy enforces that a RsaKeyValue must be present in the KeyValueToken but we got a "
                    + keyValueTokenSecurityEvent.getSecurityToken().getClass().getSimpleName());
                getPolicyAsserter().unassertPolicy(new QName(namespace, SPConstants.RSA_KEY_VALUE),
                                                   getErrorMessage());
                return false;
            } else {
                getPolicyAsserter().assertPolicy(new QName(namespace, SPConstants.RSA_KEY_VALUE));
            }
        }
        //always return true to prevent false alarm in case additional tokens with the same usage
        //appears in the message but do not fulfill the policy and are also not needed to fulfil the policy.
        getPolicyAsserter().assertPolicy(getAssertion());
        return true;
    }
}
