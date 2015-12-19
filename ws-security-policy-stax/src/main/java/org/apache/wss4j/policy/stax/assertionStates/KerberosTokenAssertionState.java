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
import org.apache.wss4j.policy.model.KerberosToken;
import org.apache.wss4j.policy.stax.PolicyAsserter;
import org.apache.wss4j.stax.securityToken.KerberosServiceSecurityToken;
import org.apache.wss4j.stax.securityToken.WSSecurityTokenConstants;
import org.apache.xml.security.stax.securityEvent.SecurityEventConstants;
import org.apache.xml.security.stax.securityEvent.TokenSecurityEvent;
import org.apache.xml.security.stax.securityToken.SecurityToken;
import org.apache.wss4j.stax.securityEvent.KerberosTokenSecurityEvent;
import org.apache.wss4j.stax.securityEvent.WSSecurityEventConstants;

/**
 * WSP1.3, 5.4.4 KerberosToken Assertion
 */

public class KerberosTokenAssertionState extends TokenAssertionState {

    public KerberosTokenAssertionState(AbstractSecurityAssertion assertion, boolean asserted,
                                       PolicyAsserter policyAsserter, boolean initiator) {
        super(assertion, asserted, policyAsserter, initiator);

        if (asserted) {
            KerberosToken token = (KerberosToken) getAssertion();
            String namespace = token.getName().getNamespaceURI();
            if (token.isRequireKeyIdentifierReference()) {
                getPolicyAsserter().assertPolicy(new QName(namespace, SPConstants.REQUIRE_KEY_IDENTIFIER_REFERENCE));
            }
            if (token.getApReqTokenType() != null) {
                getPolicyAsserter().assertPolicy(new QName(namespace, token.getApReqTokenType().name()));
            }
        }
    }

    @Override
    public SecurityEventConstants.Event[] getSecurityEventType() {
        return new SecurityEventConstants.Event[]{
                WSSecurityEventConstants.KerberosToken
        };
    }

    @Override
    public boolean assertToken(TokenSecurityEvent<? extends SecurityToken> tokenSecurityEvent,
                               AbstractToken abstractToken) throws WSSPolicyException {
        if (!(tokenSecurityEvent instanceof KerberosTokenSecurityEvent)) {
            throw new WSSPolicyException("Expected a KerberosTokenSecurityEvent but got " + tokenSecurityEvent.getClass().getName());
        }

        KerberosToken kerberosToken = (KerberosToken) abstractToken;
        KerberosTokenSecurityEvent kerberosTokenSecurityEvent = (KerberosTokenSecurityEvent) tokenSecurityEvent;
        KerberosServiceSecurityToken kerberosServiceSecurityToken = kerberosTokenSecurityEvent.getSecurityToken();

        if (kerberosToken.getIssuerName() != null &&
            !kerberosToken.getIssuerName().equals(kerberosTokenSecurityEvent.getIssuerName())) {
            setErrorMessage("IssuerName in Policy (" + kerberosToken.getIssuerName() + ") didn't match with the one in the IssuedToken (" + kerberosTokenSecurityEvent.getIssuerName() + ")");
            getPolicyAsserter().unassertPolicy(getAssertion(), getErrorMessage());
            return false;
        }

        String namespace = getAssertion().getName().getNamespaceURI();
        if (kerberosToken.isRequireKeyIdentifierReference()) {
            if (!WSSecurityTokenConstants.KeyIdentifier_EmbeddedKeyIdentifierRef.equals(kerberosServiceSecurityToken.getKeyIdentifier())) {
                setErrorMessage("Policy enforces KeyIdentifierReference but we got " + kerberosServiceSecurityToken.getKeyIdentifier());
                getPolicyAsserter().unassertPolicy(new QName(namespace, SPConstants.REQUIRE_KEY_IDENTIFIER_REFERENCE),
                                                 getErrorMessage());
                return false;
            } else {
                getPolicyAsserter().assertPolicy(new QName(namespace, SPConstants.REQUIRE_KEY_IDENTIFIER_REFERENCE));
            }
        }
        if (kerberosToken.getApReqTokenType() != null) {
            switch (kerberosToken.getApReqTokenType()) {
                case WssKerberosV5ApReqToken11:
                    if (!kerberosTokenSecurityEvent.isKerberosV5ApReqToken11()) {
                        setErrorMessage("Policy enforces " + kerberosToken.getApReqTokenType());
                        getPolicyAsserter().unassertPolicy(new QName(namespace, "WssKerberosV5ApReqToken11"),
                                                           getErrorMessage());
                        return false;
                    }
                    getPolicyAsserter().assertPolicy(new QName(namespace, "WssKerberosV5ApReqToken11"));
                    break;
                case WssGssKerberosV5ApReqToken11:
                    if (!kerberosTokenSecurityEvent.isGssKerberosV5ApReqToken11()) {
                        setErrorMessage("Policy enforces " + kerberosToken.getApReqTokenType());
                        getPolicyAsserter().unassertPolicy(new QName(namespace, "WssGssKerberosV5ApReqToken11"),
                                                           getErrorMessage());
                        return false;
                    }
                    getPolicyAsserter().assertPolicy(new QName(namespace, "WssGssKerberosV5ApReqToken11"));
                    break;
            }
        }
        //always return true to prevent false alarm in case additional tokens with the same usage
        //appears in the message but do not fulfill the policy and are also not needed to fulfil the policy.
        getPolicyAsserter().assertPolicy(getAssertion());
        return true;
    }
}
