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
import org.apache.wss4j.policy.model.SecurityContextToken;
import org.apache.wss4j.policy.stax.PolicyAsserter;
import org.apache.xml.security.stax.securityEvent.SecurityEventConstants;
import org.apache.xml.security.stax.securityEvent.TokenSecurityEvent;
import org.apache.xml.security.stax.securityToken.SecurityToken;
import org.apache.wss4j.api.stax.securityEvent.SecurityContextTokenSecurityEvent;
import org.apache.wss4j.api.stax.securityEvent.WSSecurityEventConstants;

/**
 * WSP1.3, 5.4.6 SecurityContextToken Assertion
 */

public class SecurityContextTokenAssertionState extends TokenAssertionState {

    public SecurityContextTokenAssertionState(AbstractSecurityAssertion assertion, boolean asserted,
                                              PolicyAsserter policyAsserter, boolean initiator) {
        super(assertion, asserted, policyAsserter, initiator);

        if (asserted) {
            SecurityContextToken token = (SecurityContextToken) getAssertion();
            String namespace = token.getName().getNamespaceURI();
            if (token.isRequireExternalUriReference()) {
                getPolicyAsserter().assertPolicy(new QName(namespace, SPConstants.REQUIRE_EXTERNAL_URI_REFERENCE));
            }
            if (token.isSc10SecurityContextToken()) {
                getPolicyAsserter().assertPolicy(new QName(namespace, SPConstants.SC10_SECURITY_CONTEXT_TOKEN));
            }
            if (token.isSc13SecurityContextToken()) {
                getPolicyAsserter().assertPolicy(new QName(namespace, SPConstants.SC13_SECURITY_CONTEXT_TOKEN));
            }
        }
    }

    @Override
    public SecurityEventConstants.Event[] getSecurityEventType() {
        return new SecurityEventConstants.Event[]{
                WSSecurityEventConstants.SECURITY_CONTEXT_TOKEN
        };
    }

    @Override
    public boolean assertToken(TokenSecurityEvent<? extends SecurityToken> tokenSecurityEvent,
                               AbstractToken abstractToken) throws WSSPolicyException {
        if (!(tokenSecurityEvent instanceof SecurityContextTokenSecurityEvent)) {
            throw new WSSPolicyException("Expected a SecurityContextTokenSecurityEvent but got " + tokenSecurityEvent.getClass().getName());
        }
        SecurityContextTokenSecurityEvent securityContextTokenSecurityEvent = (SecurityContextTokenSecurityEvent) tokenSecurityEvent;
        SecurityContextToken securityContextToken = (SecurityContextToken) abstractToken;

        if (securityContextToken.getIssuerName() != null
            && !securityContextToken.getIssuerName().equals(securityContextTokenSecurityEvent.getIssuerName())) {
            setErrorMessage("IssuerName in Policy (" + securityContextToken.getIssuerName()
                + ") didn't match with the one in the SecurityContextToken (" + securityContextTokenSecurityEvent.getIssuerName() + ")");
            getPolicyAsserter().unassertPolicy(getAssertion(), getErrorMessage());
            return false;
        }

        String namespace = getAssertion().getName().getNamespaceURI();
        if (securityContextToken.isRequireExternalUriReference()) {
            if (!securityContextTokenSecurityEvent.isExternalUriRef()) {
                setErrorMessage("Policy enforces externalUriRef but we didn't got one");
                getPolicyAsserter().unassertPolicy(new QName(namespace, SPConstants.REQUIRE_EXTERNAL_URI_REFERENCE),
                                                   getErrorMessage());
                return false;
            } else {
                getPolicyAsserter().assertPolicy(new QName(namespace, SPConstants.REQUIRE_EXTERNAL_URI_REFERENCE));
            }
        }
        //todo sp:SC13SecurityContextToken:
        //always return true to prevent false alarm in case additional tokens with the same usage
        //appears in the message but do not fulfill the policy and are also not needed to fulfil the policy.
        if (securityContextToken.isSc10SecurityContextToken()) {
            getPolicyAsserter().assertPolicy(new QName(namespace, SPConstants.SC10_SECURITY_CONTEXT_TOKEN));
        }
        if (securityContextToken.isSc13SecurityContextToken()) {
            getPolicyAsserter().assertPolicy(new QName(namespace, SPConstants.SC13_SECURITY_CONTEXT_TOKEN));
        }

        getPolicyAsserter().assertPolicy(getAssertion());
        return true;
    }
}
