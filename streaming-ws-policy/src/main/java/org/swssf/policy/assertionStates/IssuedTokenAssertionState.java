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
import org.apache.ws.secpolicy.model.IssuedToken;
import org.swssf.wss.securityEvent.IssuedTokenSecurityEvent;
import org.swssf.wss.securityEvent.SecurityEvent;
import org.swssf.wss.securityEvent.TokenSecurityEvent;

/**
 * WSP1.3, 5.4.2 IssuedToken Assertion
 *
 * @author $Author$
 * @version $Revision$ $Date$
 */

public class IssuedTokenAssertionState extends TokenAssertionState {

    public IssuedTokenAssertionState(AbstractSecurityAssertion assertion, boolean asserted) {
        super(assertion, asserted);
    }

    @Override
    public SecurityEvent.Event[] getSecurityEventType() {
        return new SecurityEvent.Event[]{
                SecurityEvent.Event.SecurityContextToken,
                SecurityEvent.Event.SamlToken,
                SecurityEvent.Event.RelToken,
        };
    }

    @Override
    public boolean assertToken(TokenSecurityEvent tokenSecurityEvent, AbstractToken abstractToken) throws WSSPolicyException {
        if (!(tokenSecurityEvent instanceof IssuedTokenSecurityEvent)) {
            throw new WSSPolicyException("Expected a IssuedTokenSecurityEvent but got " + tokenSecurityEvent.getClass().getName());
        }

        setAsserted(true);

        IssuedToken issuedToken = (IssuedToken) abstractToken;
        IssuedTokenSecurityEvent issuedTokenSecurityEvent = (IssuedTokenSecurityEvent) tokenSecurityEvent;
        if (issuedToken.getIssuerName() != null) {
            if (!issuedToken.getIssuerName().equals(issuedTokenSecurityEvent.getIssuerName())) {
                setAsserted(false);
                setErrorMessage("IssuerName in Policy (" + issuedToken.getIssuerName() + ") didn't match with the one in the IssuedToken (" + issuedTokenSecurityEvent.getIssuerName() + ")");
            }
        }
        //todo internal/external reference?

        return isAsserted();
    }
}
