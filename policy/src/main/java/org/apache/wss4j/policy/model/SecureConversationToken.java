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
package org.apache.wss4j.policy.model;

import org.apache.neethi.Assertion;
import org.apache.neethi.Policy;
import org.apache.wss4j.policy.SPConstants;
import org.w3c.dom.Element;

import javax.xml.namespace.QName;
import java.util.Iterator;
import java.util.List;

public class SecureConversationToken extends SecurityContextToken {

    private BootstrapPolicy bootstrapPolicy;

    private boolean mustNotSendCancel;
    private boolean mustNotSendAmend;
    private boolean mustNotSendRenew;

    public SecureConversationToken(SPConstants.SPVersion version, SPConstants.IncludeTokenType includeTokenType,
                                   Element issuer, String issuerName, Element claims, Policy nestedPolicy) {
        super(version, includeTokenType, issuer, issuerName, claims, nestedPolicy);

        parseNestedPolicy(nestedPolicy, this);
    }

    @Override
    public QName getName() {
        return getVersion().getSPConstants().getSecureConversationToken();
    }

    @Override
    public boolean equals(Object object) {
        if (object == this) {
            return true;
        }
        if (!(object instanceof SecureConversationToken)) {
            return false;
        }

        SecureConversationToken that = (SecureConversationToken)object;
        if (mustNotSendCancel != that.mustNotSendCancel
            || mustNotSendAmend != that.mustNotSendAmend
            || mustNotSendRenew != that.mustNotSendRenew) {
            return false;
        }

        return super.equals(object);
    }

    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + Boolean.hashCode(mustNotSendCancel);
        result = 31 * result + Boolean.hashCode(mustNotSendAmend);
        result = 31 * result + Boolean.hashCode(mustNotSendRenew);

        return 31 * result + super.hashCode();
    }

    @Override
    protected AbstractSecurityAssertion cloneAssertion(Policy nestedPolicy) {
        return new SecureConversationToken(getVersion(), getIncludeTokenType(), getIssuer(),
                                           getIssuerName(), getClaims(), nestedPolicy);
    }

    protected void parseNestedPolicy(Policy nestedPolicy, SecureConversationToken secureConversationToken) {
        Iterator<List<Assertion>> alternatives = nestedPolicy.getAlternatives();
        //we just process the first alternative
        //this means that if we have a compact policy only the first alternative is visible
        //in contrary to a normalized policy where just one alternative exists
        if (alternatives.hasNext()) {
            List<Assertion> assertions = alternatives.next();
            for (Assertion assertion : assertions) {
                String assertionName = assertion.getName().getLocalPart();
                String assertionNamespace = assertion.getName().getNamespaceURI();
                QName mustNotSendCancel = getVersion().getSPConstants().getMustNotSendCancel();
                if (mustNotSendCancel.getLocalPart().equals(assertionName)
                    && mustNotSendCancel.getNamespaceURI().equals(assertionNamespace)) {
                    if (secureConversationToken.isMustNotSendCancel()) {
                        throw new IllegalArgumentException(SPConstants.ERR_INVALID_POLICY);
                    }
                    secureConversationToken.setMustNotSendCancel(true);
                    continue;
                }

                QName mustNotSendAmend = getVersion().getSPConstants().getMustNotSendAmend();
                if (mustNotSendAmend.getLocalPart().equals(assertionName)
                    && mustNotSendAmend.getNamespaceURI().equals(assertionNamespace)) {
                    if (secureConversationToken.isMustNotSendAmend()) {
                        throw new IllegalArgumentException(SPConstants.ERR_INVALID_POLICY);
                    }
                    secureConversationToken.setMustNotSendAmend(true);
                    continue;
                }

                QName mustNotSendRenew = getVersion().getSPConstants().getMustNotSendRenew();
                if (mustNotSendRenew.getLocalPart().equals(assertionName)
                    && mustNotSendRenew.getNamespaceURI().equals(assertionNamespace)) {
                    if (secureConversationToken.isMustNotSendRenew()) {
                        throw new IllegalArgumentException(SPConstants.ERR_INVALID_POLICY);
                    }
                    secureConversationToken.setMustNotSendRenew(true);
                    continue;
                }

                QName bootstrapPolicy = getVersion().getSPConstants().getBootstrapPolicy();
                if (bootstrapPolicy.getLocalPart().equals(assertionName)
                    && bootstrapPolicy.getNamespaceURI().equals(assertionNamespace)) {
                    if (secureConversationToken.getBootstrapPolicy() != null) {
                        throw new IllegalArgumentException(SPConstants.ERR_INVALID_POLICY);
                    }
                    BootstrapPolicy bootstrap = (BootstrapPolicy) assertion;
                    secureConversationToken.setBootstrapPolicy(bootstrap);
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

    public BootstrapPolicy getBootstrapPolicy() {
        return bootstrapPolicy;
    }

    protected void setBootstrapPolicy(BootstrapPolicy bootstrapPolicy) {
        this.bootstrapPolicy = bootstrapPolicy;
    }
}
