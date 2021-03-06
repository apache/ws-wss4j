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

public class RelToken extends AbstractToken {

    public enum RelTokenType {
        WssRelV10Token10,
        WssRelV20Token10,
        WssRelV10Token11,
        WssRelV20Token11;

        private static final Map<String, RelTokenType> LOOKUP = new HashMap<>();

        static {
            for (RelTokenType u : EnumSet.allOf(RelTokenType.class)) {
                LOOKUP.put(u.name(), u);
            }
        }

        public static RelTokenType lookUp(String name) {
            return LOOKUP.get(name);
        }
    }

    private boolean requireKeyIdentifierReference;
    private RelTokenType relTokenType;

    public RelToken(SPConstants.SPVersion version, SPConstants.IncludeTokenType includeTokenType,
                    Element issuer, String issuerName, Element claims, Policy nestedPolicy) {
        super(version, includeTokenType, issuer, issuerName, claims, nestedPolicy);

        parseNestedPolicy(nestedPolicy, this);
    }

    @Override
    public QName getName() {
        return getVersion().getSPConstants().getRelToken();
    }

    @Override
    public boolean equals(Object object) {
        if (object == this) {
            return true;
        }
        if (!(object instanceof RelToken)) {
            return false;
        }

        RelToken that = (RelToken)object;
        if (requireKeyIdentifierReference != that.requireKeyIdentifierReference) {
            return false;
        }
        if (relTokenType != that.relTokenType) {
            return false;
        }

        return super.equals(object);
    }

    @Override
    public int hashCode() {
        int result = 17;
        if (relTokenType != null) {
            result = 31 * result + relTokenType.hashCode();
        }
        result = 31 * result + Boolean.hashCode(requireKeyIdentifierReference);

        return 31 * result + super.hashCode();
    }

    @Override
    protected AbstractSecurityAssertion cloneAssertion(Policy nestedPolicy) {
        return new RelToken(getVersion(), getIncludeTokenType(), getIssuer(), getIssuerName(),
                            getClaims(), nestedPolicy);
    }

    protected void parseNestedPolicy(Policy nestedPolicy, RelToken relToken) {
        Iterator<List<Assertion>> alternatives = nestedPolicy.getAlternatives();
        //we just process the first alternative
        //this means that if we have a compact policy only the first alternative is visible
        //in contrary to a normalized policy where just one alternative exists
        if (alternatives.hasNext()) {
            List<Assertion> assertions = alternatives.next();
            for (Assertion assertion : assertions) {
                String assertionName = assertion.getName().getLocalPart();
                String assertionNamespace = assertion.getName().getNamespaceURI();
                DerivedKeys derivedKeys = DerivedKeys.lookUp(assertionName);
                if (derivedKeys != null) {
                    if (relToken.getDerivedKeys() != null) {
                        throw new IllegalArgumentException(SPConstants.ERR_INVALID_POLICY);
                    }
                    relToken.setDerivedKeys(derivedKeys);
                    continue;
                }
                QName requireKeyIdentifierRef =
                    getVersion().getSPConstants().getRequireKeyIdentifierReference();
                if (requireKeyIdentifierRef.getLocalPart().equals(assertionName)
                    && requireKeyIdentifierRef.getNamespaceURI().equals(assertionNamespace)) {
                    if (relToken.isRequireKeyIdentifierReference()) {
                        throw new IllegalArgumentException(SPConstants.ERR_INVALID_POLICY);
                    }
                    relToken.setRequireKeyIdentifierReference(true);
                    continue;
                }
                RelTokenType samlTokenType = RelTokenType.lookUp(assertionName);
                if (samlTokenType != null) {
                    if (relToken.getRelTokenType() != null) {
                        throw new IllegalArgumentException(SPConstants.ERR_INVALID_POLICY);
                    }
                    relToken.setRelTokenType(samlTokenType);
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

    public RelTokenType getRelTokenType() {
        return relTokenType;
    }

    protected void setRelTokenType(RelTokenType relTokenType) {
        this.relTokenType = relTokenType;
    }
}
