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

public class SecurityContextToken extends AbstractToken {

    private boolean requireExternalUriReference;
    private boolean sc13SecurityContextToken;
    private boolean sc10SecurityContextToken;

    public SecurityContextToken(SPConstants.SPVersion version, SPConstants.IncludeTokenType includeTokenType,
                                Element issuer, String issuerName, Element claims, Policy nestedPolicy) {
        super(version, includeTokenType, issuer, issuerName, claims, nestedPolicy);

        parseNestedSecurityContextTokenPolicy(nestedPolicy, this);
    }

    @Override
    public QName getName() {
        return getVersion().getSPConstants().getSecurityContextToken();
    }
    
    @Override
    public boolean equals(Object object) {
        if (object == this) {
            return true;
        }
        if (!(object instanceof SecurityContextToken)) {
            return false;
        }
        
        SecurityContextToken that = (SecurityContextToken)object;
        if (requireExternalUriReference != that.requireExternalUriReference
            || sc13SecurityContextToken != that.sc13SecurityContextToken
            || sc10SecurityContextToken != that.sc10SecurityContextToken) {
            return false;
        }
        
        return super.equals(object);
    }
    
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + Boolean.valueOf(requireExternalUriReference).hashCode();
        result = 31 * result + Boolean.valueOf(sc13SecurityContextToken).hashCode();
        result = 31 * result + Boolean.valueOf(sc10SecurityContextToken).hashCode();
        
        return 31 * result + super.hashCode();
    }

    @Override
    protected AbstractSecurityAssertion cloneAssertion(Policy nestedPolicy) {
        return new SecurityContextToken(getVersion(), getIncludeTokenType(), getIssuer(),
                                        getIssuerName(), getClaims(), nestedPolicy);
    }

    protected void parseNestedSecurityContextTokenPolicy(Policy nestedPolicy,
                                                         SecurityContextToken securityContextToken) {
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
                DerivedKeys derivedKeys = DerivedKeys.lookUp(assertionName);
                if (derivedKeys != null) {
                    if (securityContextToken.getDerivedKeys() != null) {
                        throw new IllegalArgumentException(SPConstants.ERR_INVALID_POLICY);
                    }
                    securityContextToken.setDerivedKeys(derivedKeys);
                    continue;
                }

                QName requireExternalUriRef = getVersion().getSPConstants().getRequireExternalUriReference();
                if (requireExternalUriRef.getLocalPart().equals(assertionName)
                    && requireExternalUriRef.getNamespaceURI().equals(assertionNamespace)) {
                    if (securityContextToken.isRequireExternalUriReference()) {
                        throw new IllegalArgumentException(SPConstants.ERR_INVALID_POLICY);
                    }
                    securityContextToken.setRequireExternalUriReference(true);
                    continue;
                }

                QName sc13SCT = getVersion().getSPConstants().getSc13SecurityContextToken();
                if (sc13SCT.getLocalPart().equals(assertionName)
                    && sc13SCT.getNamespaceURI().equals(assertionNamespace)) {
                    if (securityContextToken.isSc13SecurityContextToken()) {
                        throw new IllegalArgumentException(SPConstants.ERR_INVALID_POLICY);
                    }
                    securityContextToken.setSc13SecurityContextToken(true);
                    continue;
                }

                QName sc10SCT = getVersion().getSPConstants().getSc10SecurityContextToken();
                if (sc10SCT.getLocalPart().equals(assertionName)
                    && sc10SCT.getNamespaceURI().equals(assertionNamespace)) {
                    if (securityContextToken.isSc10SecurityContextToken()) {
                        throw new IllegalArgumentException(SPConstants.ERR_INVALID_POLICY);
                    }
                    securityContextToken.setSc10SecurityContextToken(true);
                    continue;
                }
            }
        }
    }

    public boolean isRequireExternalUriReference() {
        return requireExternalUriReference;
    }

    protected void setRequireExternalUriReference(boolean requireExternalUriReference) {
        this.requireExternalUriReference = requireExternalUriReference;
    }

    public boolean isSc13SecurityContextToken() {
        return sc13SecurityContextToken;
    }

    protected void setSc13SecurityContextToken(boolean sc13SecurityContextToken) {
        this.sc13SecurityContextToken = sc13SecurityContextToken;
    }

    public boolean isSc10SecurityContextToken() {
        return sc10SecurityContextToken;
    }

    protected void setSc10SecurityContextToken(boolean sc10SecurityContextToken) {
        this.sc10SecurityContextToken = sc10SecurityContextToken;
    }
}
