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
package org.apache.ws.security.policy.stax.assertionStates;

import org.apache.ws.security.policy.WSSPolicyException;
import org.apache.ws.security.policy.model.AbstractSecurityAssertion;
import org.apache.ws.security.policy.model.AbstractToken;
import org.apache.ws.security.policy.model.SecureConversationToken;
import org.apache.xml.security.stax.securityEvent.SecurityEventConstants;
import org.apache.xml.security.stax.securityEvent.TokenSecurityEvent;
import org.swssf.wss.securityEvent.SecureConversationTokenSecurityEvent;
import org.swssf.wss.securityEvent.WSSecurityEventConstants;

/**
 * WSP1.3, 5.4.7 SecureConversationToken Assertion
 *
 * @author $Author$
 * @version $Revision$ $Date$
 */

public class SecureConversationTokenAssertionState extends TokenAssertionState {

    public SecureConversationTokenAssertionState(AbstractSecurityAssertion assertion, boolean asserted) {
        super(assertion, asserted);
    }

    @Override
    public SecurityEventConstants.Event[] getSecurityEventType() {
        return new SecurityEventConstants.Event[]{
                WSSecurityEventConstants.SecureConversationToken
        };
    }

    @Override
    public boolean assertToken(TokenSecurityEvent tokenSecurityEvent, AbstractToken abstractToken) throws WSSPolicyException {
        if (!(tokenSecurityEvent instanceof SecureConversationTokenSecurityEvent)) {
            throw new WSSPolicyException("Expected a SecureConversationSecurityEvent but got " + tokenSecurityEvent.getClass().getName());
        }
        SecureConversationTokenSecurityEvent secureConversationSecurityEvent = (SecureConversationTokenSecurityEvent) tokenSecurityEvent;
        SecureConversationToken secureConversationToken = (SecureConversationToken) abstractToken;

        if (secureConversationToken.getIssuerName() != null && !secureConversationToken.getIssuerName().equals(secureConversationSecurityEvent.getIssuerName())) {
            setErrorMessage("IssuerName in Policy (" + secureConversationToken.getIssuerName() + ") didn't match with the one in the SecureConversationToken (" + secureConversationSecurityEvent.getIssuerName() + ")");
            return false;
        }
        if (secureConversationToken.isRequireExternalUriReference() && !secureConversationSecurityEvent.isExternalUriRef()) {
            setErrorMessage("Policy enforces externalUriRef but we didn't got one");
            return false;
        }
        //todo sp:SC13SecurityContextToken:
        //todo MustNotSendCancel etc...
        //always return true to prevent false alarm in case additional tokens with the same usage
        //appears in the message but do not fulfill the policy and are also not needed to fulfil the policy.
        return true;
    }
}
