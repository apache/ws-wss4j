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
package org.apache.ws.secpolicy.model;

import org.apache.neethi.Assertion;
import org.apache.neethi.Policy;
import org.apache.neethi.builders.PolicyContainingPrimitiveAssertion;
import org.apache.ws.secpolicy.SPConstants;
import org.w3c.dom.Element;

import javax.xml.namespace.QName;
import java.util.Iterator;
import java.util.List;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class SecureConversationToken extends SecurityContextToken {

    private Policy bootstrapPolicy;

    private boolean mustNotSendCancel;
    private boolean mustNotSendAmend;
    private boolean mustNotSendRenew;

    public SecureConversationToken(SPConstants.SPVersion version, SPConstants.IncludeTokenType includeTokenType,
                                   Element issuer, String issuerName, Element claims, Policy nestedPolicy) {
        super(version, includeTokenType, issuer, issuerName, claims, nestedPolicy);

        parseNestedPolicy(nestedPolicy, this);
    }

    public QName getName() {
        return getVersion().getSPConstants().getSecureConversationToken();
    }

    @Override
    protected AbstractSecurityAssertion cloneAssertion(Policy nestedPolicy) {
        return new SecureConversationToken(getVersion(), getIncludeTokenType(), getIssuer(), getIssuerName(), getClaims(), nestedPolicy);
    }

    protected void parseNestedPolicy(Policy nestedPolicy, SecureConversationToken secureConversationToken) {
        Iterator<List<Assertion>> alternatives = nestedPolicy.getAlternatives();
        //we just process the first alternative
        //this means that if we have a compact policy only the first alternative is visible
        //in contrary to a normalized policy where just one alternative exists
        if (alternatives.hasNext()) {
            List<Assertion> assertions = alternatives.next();
            for (int i = 0; i < assertions.size(); i++) {
                Assertion assertion = assertions.get(i);
                String assertionName = assertion.getName().getLocalPart();
                String assertionNamespace = assertion.getName().getNamespaceURI();
                if (getVersion().getSPConstants().getMustNotSendCancel().getLocalPart().equals(assertionName)
                        && getVersion().getSPConstants().getMustNotSendCancel().getNamespaceURI().equals(assertionNamespace)) {
                    if (secureConversationToken.isMustNotSendCancel()) {
                        throw new IllegalArgumentException(SPConstants.ERR_INVALID_POLICY);
                    }
                    secureConversationToken.setMustNotSendCancel(true);
                    continue;
                }
                if (getVersion().getSPConstants().getMustNotSendAmend().getLocalPart().equals(assertionName)
                        && getVersion().getSPConstants().getMustNotSendAmend().getNamespaceURI().equals(assertionNamespace)) {
                    if (secureConversationToken.isMustNotSendAmend()) {
                        throw new IllegalArgumentException(SPConstants.ERR_INVALID_POLICY);
                    }
                    secureConversationToken.setMustNotSendAmend(true);
                    continue;
                }
                if (getVersion().getSPConstants().getMustNotSendRenew().getLocalPart().equals(assertionName)
                        && getVersion().getSPConstants().getMustNotSendRenew().getNamespaceURI().equals(assertionNamespace)) {
                    if (secureConversationToken.isMustNotSendRenew()) {
                        throw new IllegalArgumentException(SPConstants.ERR_INVALID_POLICY);
                    }
                    secureConversationToken.setMustNotSendRenew(true);
                    continue;
                }
                if (getVersion().getSPConstants().getBootstrapPolicy().getLocalPart().equals(assertionName)
                        && getVersion().getSPConstants().getBootstrapPolicy().getNamespaceURI().equals(assertionNamespace)) {
                    if (secureConversationToken.getBootstrapPolicy() != null) {
                        throw new IllegalArgumentException(SPConstants.ERR_INVALID_POLICY);
                    }
                    PolicyContainingPrimitiveAssertion policyContainingPrimitiveAssertion = (PolicyContainingPrimitiveAssertion) assertion;
                    secureConversationToken.setBootstrapPolicy(policyContainingPrimitiveAssertion.getPolicy());
                    continue;
                }
            }
        }
    }

    public boolean isMustNotSendCancel() {
        return mustNotSendCancel;
    }

    protected void setMustNotSendCancel(boolean mustNotSendCancel) {
        this.mustNotSendCancel = mustNotSendCancel;
    }

    public boolean isMustNotSendAmend() {
        return mustNotSendAmend;
    }

    protected void setMustNotSendAmend(boolean mustNotSendAmend) {
        this.mustNotSendAmend = mustNotSendAmend;
    }

    public boolean isMustNotSendRenew() {
        return mustNotSendRenew;
    }

    protected void setMustNotSendRenew(boolean mustNotSendRenew) {
        this.mustNotSendRenew = mustNotSendRenew;
    }

    public Policy getBootstrapPolicy() {
        return bootstrapPolicy;
    }

    protected void setBootstrapPolicy(Policy bootstrapPolicy) {
        this.bootstrapPolicy = bootstrapPolicy;
    }
}
