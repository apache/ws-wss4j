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
import org.apache.wss4j.policy.model.HttpsToken;
import org.apache.wss4j.policy.stax.PolicyAsserter;
import org.apache.xml.security.stax.securityEvent.SecurityEventConstants;
import org.apache.xml.security.stax.securityEvent.TokenSecurityEvent;
import org.apache.xml.security.stax.securityToken.SecurityToken;
import org.apache.wss4j.stax.securityEvent.HttpsTokenSecurityEvent;
import org.apache.wss4j.stax.securityEvent.WSSecurityEventConstants;

/**
 * WSP1.3, 5.4.10 HttpsToken Assertion
 */

public class HttpsTokenAssertionState extends TokenAssertionState {

    public HttpsTokenAssertionState(AbstractSecurityAssertion assertion, boolean asserted,
                                    PolicyAsserter policyAsserter, boolean initiator) {
        super(assertion, asserted, policyAsserter, initiator);
        
        if (asserted) {
            HttpsToken token = (HttpsToken) getAssertion();
            String namespace = token.getName().getNamespaceURI();
            if (token.getAuthenticationType() != null) {
                getPolicyAsserter().assertPolicy(new QName(namespace, token.getAuthenticationType().name()));
            }
        }
    }

    @Override
    public SecurityEventConstants.Event[] getSecurityEventType() {
        return new SecurityEventConstants.Event[]{
                WSSecurityEventConstants.HttpsToken
        };
    }

    @Override
    public boolean assertToken(TokenSecurityEvent<? extends SecurityToken> tokenSecurityEvent,
                               AbstractToken abstractToken) throws WSSPolicyException {
        if (!(tokenSecurityEvent instanceof HttpsTokenSecurityEvent)) {
            throw new WSSPolicyException("Expected a HttpsTokenSecurityEvent but got " + tokenSecurityEvent.getClass().getName());
        }

        HttpsTokenSecurityEvent httpsTokenSecurityEvent = (HttpsTokenSecurityEvent) tokenSecurityEvent;
        HttpsToken httpsToken = (HttpsToken) abstractToken;

        if (httpsToken.getIssuerName() != null && !httpsToken.getIssuerName().equals(httpsTokenSecurityEvent.getIssuerName())) {
            setErrorMessage("IssuerName in Policy (" + httpsToken.getIssuerName() + ") didn't match with the one in the HttpsToken (" + httpsTokenSecurityEvent.getIssuerName() + ")");
            getPolicyAsserter().unassertPolicy(getAssertion(), getErrorMessage());
            return false;
        }
        if (!isInitiator() && httpsToken.getAuthenticationType() != null) {
            String namespace = getAssertion().getName().getNamespaceURI();
            
            switch (httpsToken.getAuthenticationType()) {
                case HttpBasicAuthentication:
                    if (httpsTokenSecurityEvent.getAuthenticationType() != HttpsTokenSecurityEvent.AuthenticationType.HttpBasicAuthentication) {
                        setErrorMessage("Policy enforces HttpBasicAuthentication but we got " + httpsTokenSecurityEvent.getAuthenticationType());
                        getPolicyAsserter().unassertPolicy(new QName(namespace, SPConstants.HTTP_BASIC_AUTHENTICATION),
                                                         getErrorMessage());
                        return false;
                    }
                    getPolicyAsserter().assertPolicy(new QName(namespace, SPConstants.HTTP_BASIC_AUTHENTICATION));
                    break;
                case HttpDigestAuthentication:
                    if (httpsTokenSecurityEvent.getAuthenticationType() != HttpsTokenSecurityEvent.AuthenticationType.HttpDigestAuthentication) {
                        setErrorMessage("Policy enforces HttpDigestAuthentication but we got " + httpsTokenSecurityEvent.getAuthenticationType());
                        getPolicyAsserter().unassertPolicy(new QName(namespace, SPConstants.HTTP_DIGEST_AUTHENTICATION),
                                                           getErrorMessage());
                        return false;
                    }
                    getPolicyAsserter().assertPolicy(new QName(namespace, SPConstants.HTTP_DIGEST_AUTHENTICATION));
                    break;
                case RequireClientCertificate:
                    if (httpsTokenSecurityEvent.getAuthenticationType() != HttpsTokenSecurityEvent.AuthenticationType.HttpsClientCertificateAuthentication) {
                        setErrorMessage("Policy enforces HttpClientCertificateAuthentication but we got " + httpsTokenSecurityEvent.getAuthenticationType());
                        getPolicyAsserter().unassertPolicy(new QName(namespace, SPConstants.REQUIRE_CLIENT_CERTIFICATE),
                                                           getErrorMessage());
                        return false;
                    }
                    getPolicyAsserter().assertPolicy(new QName(namespace, SPConstants.REQUIRE_CLIENT_CERTIFICATE));
                    break;
            }
        }
        
        getPolicyAsserter().assertPolicy(getAssertion());
        return true;
    }
}
