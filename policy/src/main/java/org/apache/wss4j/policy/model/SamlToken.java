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
import java.util.*;

public class SamlToken extends AbstractToken {

    public enum SamlTokenType {
        WssSamlV10Token10,
        WssSamlV11Token10,
        WssSamlV10Token11,
        WssSamlV11Token11,
        WssSamlV20Token11;

        private static final Map<String, SamlTokenType> lookup = new HashMap<String, SamlTokenType>();

        static {
            for (SamlTokenType u : EnumSet.allOf(SamlTokenType.class))
                lookup.put(u.name(), u);
        }

        public static SamlTokenType lookUp(String name) {
            return lookup.get(name);
        }
    }

    private boolean requireKeyIdentifierReference;
    private SamlTokenType samlTokenType;

    public SamlToken(SPConstants.SPVersion version, SPConstants.IncludeTokenType includeTokenType,
                     Element issuer, String issuerName, Element claims, Policy nestedPolicy) {
        super(version, includeTokenType, issuer, issuerName, claims, nestedPolicy);

        parseNestedPolicy(nestedPolicy, this);
    }

    @Override
    public QName getName() {
        return getVersion().getSPConstants().getSamlToken();
    }

    @Override
    protected AbstractSecurityAssertion cloneAssertion(Policy nestedPolicy) {
        return new SamlToken(getVersion(), getIncludeTokenType(), getIssuer(), getIssuerName(), getClaims(), nestedPolicy);
    }

    protected void parseNestedPolicy(Policy nestedPolicy, SamlToken samlToken) {
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
                    if (samlToken.getDerivedKeys() != null) {
                        throw new IllegalArgumentException(SPConstants.ERR_INVALID_POLICY);
                    }
                    samlToken.setDerivedKeys(derivedKeys);
                    continue;
                }
                if (getVersion().getSPConstants().getRequireKeyIdentifierReference().getLocalPart().equals(assertionName)
                        && getVersion().getSPConstants().getRequireKeyIdentifierReference().getNamespaceURI().equals(assertionNamespace)) {
                    if (samlToken.isRequireKeyIdentifierReference()) {
                        throw new IllegalArgumentException(SPConstants.ERR_INVALID_POLICY);
                    }
                    samlToken.setRequireKeyIdentifierReference(true);
                    continue;
                }
                SamlTokenType samlTokenType = SamlTokenType.lookUp(assertionName);
                if (samlTokenType != null) {
                    if (samlToken.getSamlTokenType() != null) {
                        throw new IllegalArgumentException(SPConstants.ERR_INVALID_POLICY);
                    }
                    samlToken.setSamlTokenType(samlTokenType);
                    continue;
                }
            }
        }
    }

    public boolean isRequireKeyIdentifierReference() {
        return requireKeyIdentifierReference;
    }

    public void setRequireKeyIdentifierReference(boolean requireKeyIdentifierReference) {
        this.requireKeyIdentifierReference = requireKeyIdentifierReference;
    }

    public SamlTokenType getSamlTokenType() {
        return samlTokenType;
    }

    protected void setSamlTokenType(SamlTokenType samlTokenType) {
        this.samlTokenType = samlTokenType;
    }
}
