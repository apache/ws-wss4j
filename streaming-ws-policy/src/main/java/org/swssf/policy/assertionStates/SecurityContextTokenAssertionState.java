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
import org.apache.ws.secpolicy.model.SecurityContextToken;
import org.swssf.wss.securityEvent.SecurityContextTokenSecurityEvent;
import org.swssf.wss.securityEvent.SecurityEvent;
import org.swssf.wss.securityEvent.TokenSecurityEvent;

/**
 * @author $Author: giger $
 * @version $Revision: 1197077 $ $Date: 2011-11-03 13:17:40 +0100 (Don, 03. Nov 2011) $
 */

public class SecurityContextTokenAssertionState extends TokenAssertionState {

    public SecurityContextTokenAssertionState(AbstractSecurityAssertion assertion, boolean asserted) {
        super(assertion, asserted);
    }

    @Override
    public SecurityEvent.Event[] getSecurityEventType() {
        return new SecurityEvent.Event[]{
                SecurityEvent.Event.SecurityContextToken
        };
    }

    @Override
    public void assertToken(TokenSecurityEvent tokenSecurityEvent, AbstractToken abstractToken) throws WSSPolicyException {
        if (!(tokenSecurityEvent instanceof SecurityContextTokenSecurityEvent)) {
            throw new WSSPolicyException("Expected a SecurityContextTokenSecurityEvent but got " + tokenSecurityEvent.getClass().getName());
        }
        SecurityContextTokenSecurityEvent securityContextTokenSecurityEvent = (SecurityContextTokenSecurityEvent) tokenSecurityEvent;
        SecurityContextToken securityContextToken = (SecurityContextToken) abstractToken;

        setAsserted(true);
        //todo move issuerName to superClass?
        if (securityContextToken.getIssuerName() != null && !securityContextToken.getIssuerName().equals(securityContextTokenSecurityEvent.getIssuerName())) {
            setAsserted(false);
            setErrorMessage("IssuerName in Policy (" + securityContextToken.getIssuerName() + ") didn't match with the one in the SecurityContextToken (" + securityContextTokenSecurityEvent.getIssuerName() + ")");
        }
        if (securityContextToken.isRequireExternalUriReference() && !securityContextTokenSecurityEvent.isExternalUriRef()) {
            setAsserted(false);
            setErrorMessage("Policy enforces externalUriRef but we didn't got one");
        }
        //todo sp:SC13SecurityContextToken:
        //if (securityContextToken.isSc10SecurityContextToken() && )
    }
}
