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
import org.apache.wss4j.policy.model.RelToken;
import org.apache.xml.security.stax.securityEvent.SecurityEventConstants;
import org.apache.xml.security.stax.securityEvent.TokenSecurityEvent;
import org.apache.wss4j.stax.securityEvent.RelTokenSecurityEvent;
import org.apache.wss4j.stax.securityEvent.WSSecurityEventConstants;

/**
 * WSP1.3, 5.4.9 RelToken Assertion
 *
 * @author $Author$
 * @version $Revision$ $Date$
 */

public class RelTokenAssertionState extends TokenAssertionState {

    public RelTokenAssertionState(AbstractSecurityAssertion assertion, boolean asserted) {
        super(assertion, asserted);
    }

    @Override
    public SecurityEventConstants.Event[] getSecurityEventType() {
        return new SecurityEventConstants.Event[]{
                WSSecurityEventConstants.RelToken
        };
    }

    @Override
    public boolean assertToken(TokenSecurityEvent tokenSecurityEvent, AbstractToken abstractToken) throws WSSPolicyException {
        if (!(tokenSecurityEvent instanceof RelTokenSecurityEvent)) {
            throw new WSSPolicyException("Expected a RelTokenSecurityEvent but got " + tokenSecurityEvent.getClass().getName());
        }

        RelTokenSecurityEvent relTokenSecurityEvent = (RelTokenSecurityEvent) tokenSecurityEvent;
        RelToken relToken = (RelToken) abstractToken;

        if (relToken.getIssuerName() != null && !relToken.getIssuerName().equals(relTokenSecurityEvent.getIssuerName())) {
            setErrorMessage("IssuerName in Policy (" + relToken.getIssuerName() + ") didn't match with the one in the RelToken (" + relTokenSecurityEvent.getIssuerName() + ")");
            return false;
        }

        //todo RequireKeyIdentifierReference
        //todo WssRelV*
        //always return true to prevent false alarm in case additional tokens with the same usage
        //appears in the message but do not fulfill the policy and are also not needed to fulfil the policy.
        return true;
    }
}
