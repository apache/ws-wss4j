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
import org.apache.ws.secpolicy.model.SamlToken;
import org.opensaml.common.SAMLVersion;
import org.swssf.wss.ext.WSSConstants;
import org.swssf.wss.impl.securityToken.AbstractSecurityToken;
import org.swssf.wss.securityEvent.SamlTokenSecurityEvent;
import org.swssf.wss.securityEvent.SecurityEvent;
import org.swssf.wss.securityEvent.TokenSecurityEvent;
import org.swssf.xmlsec.ext.XMLSecurityException;

/**
 * WSP1.3, 5.4.8 SamlToken Assertion
 *
 * @author $Author$
 * @version $Revision$ $Date$
 */

public class SamlTokenAssertionState extends TokenAssertionState {

    public SamlTokenAssertionState(AbstractSecurityAssertion assertion, boolean asserted) {
        super(assertion, asserted);
    }

    @Override
    public SecurityEvent.Event[] getSecurityEventType() {
        return new SecurityEvent.Event[]{
                SecurityEvent.Event.SamlToken
        };
    }

    @Override
    public boolean assertToken(TokenSecurityEvent tokenSecurityEvent, AbstractToken abstractToken) throws WSSPolicyException, XMLSecurityException {
        if (!(tokenSecurityEvent instanceof SamlTokenSecurityEvent)) {
            throw new WSSPolicyException("Expected a SamlTokenSecurityEvent but got " + tokenSecurityEvent.getClass().getName());
        }
        SamlTokenSecurityEvent samlTokenSecurityEvent = (SamlTokenSecurityEvent) tokenSecurityEvent;
        SamlToken samlToken = (SamlToken) abstractToken;

        if (samlToken.getIssuerName() != null && !samlToken.getIssuerName().equals(samlTokenSecurityEvent.getIssuerName())) {
            setErrorMessage("IssuerName in Policy (" + samlToken.getIssuerName() + ") didn't match with the one in the SamlToken (" + samlTokenSecurityEvent.getIssuerName() + ")");
            return false;
        }
        if (samlToken.isRequireKeyIdentifierReference() && ((AbstractSecurityToken) samlTokenSecurityEvent.getSecurityToken()).getKeyIdentifierType() != WSSConstants.KeyIdentifierType.X509_KEY_IDENTIFIER) {
            setErrorMessage("Policy enforces KeyIdentifierReference but we got " + samlTokenSecurityEvent.getSecurityToken().getTokenType());
            return false;
        }
        if (samlToken.getSamlTokenType() != null) {
            switch (samlToken.getSamlTokenType()) {
                case WssSamlV11Token10:
                    if (samlTokenSecurityEvent.getSamlVersion() != SAMLVersion.VERSION_10) {
                        setErrorMessage("Policy enforces SamlVersion11Profile10 but we got " + samlTokenSecurityEvent.getSamlVersion());
                        return false;
                    }
                    break;
                case WssSamlV11Token11:
                    if (samlTokenSecurityEvent.getSamlVersion() != SAMLVersion.VERSION_11) {
                        setErrorMessage("Policy enforces SamlVersion11Profile11 but we got " + samlTokenSecurityEvent.getSamlVersion());
                        return false;
                    }
                    break;
                case WssSamlV20Token11:
                    if (samlTokenSecurityEvent.getSamlVersion() != SAMLVersion.VERSION_20) {
                        setErrorMessage("Policy enforces SamlVersion20Profile11 but we got " + samlTokenSecurityEvent.getSamlVersion());
                        return false;
                    }
                    break;
                case WssSamlV10Token10:
                case WssSamlV10Token11:
                    setErrorMessage("Unsupported token type: " + samlToken.getSamlTokenType());
                    return false;
            }
        }
        //always return true to prevent false alarm in case additional tokens with the same usage
        //appears in the message but do not fulfill the policy and are also not needed to fulfil the policy.
        return true;
    }
}
