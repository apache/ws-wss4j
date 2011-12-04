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

import org.apache.ws.secpolicy.AssertionState;
import org.apache.ws.secpolicy.WSSPolicyException;
import org.apache.ws.secpolicy.model.AbstractSecurityAssertion;
import org.apache.ws.secpolicy.model.AbstractToken;
import org.swssf.policy.Assertable;
import org.swssf.wss.securityEvent.SecurityEvent;
import org.swssf.wss.securityEvent.TokenSecurityEvent;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */

public abstract class TokenAssertionState extends AssertionState implements Assertable {

    //todo how to verify the issuer of the UsernameToken??
    //todo <sp:Issuer>wsa:EndpointReferenceType</sp:Issuer>
    //todo issuerName
    //todo claims
    //todo derived keys?

    public TokenAssertionState(AbstractSecurityAssertion assertion, boolean asserted) {
        super(assertion, asserted);
    }

    @Override
    public boolean assertEvent(SecurityEvent securityEvent) throws WSSPolicyException {

        TokenSecurityEvent tokenSecurityEvent = (TokenSecurityEvent) securityEvent;
        AbstractToken token = (AbstractToken) getAssertion();
        assertToken(tokenSecurityEvent, token);
        return isAsserted();
    }

    public abstract void assertToken(TokenSecurityEvent tokenSecurityEvent, AbstractToken abstractToken) throws WSSPolicyException;
}
