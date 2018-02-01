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

public class KerberosToken extends AbstractToken {

    public enum ApReqTokenType {
        WssKerberosV5ApReqToken11,
        WssGssKerberosV5ApReqToken11;

        private static final Map<String, ApReqTokenType> LOOKUP = new HashMap<>();

        static {
            for (ApReqTokenType u : EnumSet.allOf(ApReqTokenType.class)) {
                LOOKUP.put(u.name(), u);
            }
        }

        public static ApReqTokenType lookUp(String name) {
            return LOOKUP.get(name);
        }
    }

    private boolean requireKeyIdentifierReference;

    private ApReqTokenType apReqTokenType;

    public KerberosToken(SPConstants.SPVersion version, SPConstants.IncludeTokenType includeTokenType,
                         Element issuer, String issuerName, Element claims, Policy nestedPolicy) {
        super(version, includeTokenType, issuer, issuerName, claims, nestedPolicy);

        parseNestedPolicy(nestedPolicy, this);
    }

    @Override
    public QName getName() {
        return getVersion().getSPConstants().getKerberosToken();
    }
    
    @Override
    public boolean equals(Object object) {
        if (object == this) {
            return true;
        }
        if (!(object instanceof KerberosToken)) {
            return false;
        }
        
        KerberosToken that = (KerberosToken)object;
        if (requireKeyIdentifierReference != that.requireKeyIdentifierReference) {
            return false;
        }
        if (apReqTokenType != that.apReqTokenType) {
            return false;
        }
        
        return super.equals(object);
    }
    
    @Override
    public int hashCode() {
        int result = 17;
        if (apReqTokenType != null) {
            result = 31 * result + apReqTokenType.hashCode();
        }
        result = 31 * result + Boolean.valueOf(requireKeyIdentifierReference).hashCode();
        
        return 31 * result + super.hashCode();
    }

    @Override
    protected AbstractSecurityAssertion cloneAssertion(Policy nestedPolicy) {
        return new KerberosToken(getVersion(), getIncludeTokenType(), getIssuer(),
                                 getIssuerName(), getClaims(), nestedPolicy);
    }

    protected void parseNestedPolicy(Policy nestedPolicy, KerberosToken kerberosToken) {
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
                    if (kerberosToken.getDerivedKeys() != null) {
                        throw new IllegalArgumentException(SPConstants.ERR_INVALID_POLICY);
                    }
                    kerberosToken.setDerivedKeys(derivedKeys);
                    continue;
                }
                QName requireKeyIdentifierRef =
                    getVersion().getSPConstants().getRequireKeyIdentifierReference();
                if (requireKeyIdentifierRef.getLocalPart().equals(assertionName)
                    && requireKeyIdentifierRef.getNamespaceURI().equals(assertionNamespace)) {
                    if (kerberosToken.isRequireKeyIdentifierReference()) {
                        throw new IllegalArgumentException(SPConstants.ERR_INVALID_POLICY);
                    }
                    kerberosToken.setRequireKeyIdentifierReference(true);
                    continue;
                }
                ApReqTokenType apReqTokenType = ApReqTokenType.lookUp(assertionName);
                if (apReqTokenType != null) {
                    if (kerberosToken.getApReqTokenType() != null) {
                        throw new IllegalArgumentException(SPConstants.ERR_INVALID_POLICY);
                    }
                    kerberosToken.setApReqTokenType(apReqTokenType);
                    continue;
                }
            }
        }
    }

    public boolean isRequireKeyIdentifierReference() {
        return requireKeyIdentifierReference;
    }

    protected void setRequireKeyIdentifierReference(boolean requireKeyIdentifierReference) {
        this.requireKeyIdentifierReference = requireKeyIdentifierReference;
    }

    public ApReqTokenType getApReqTokenType() {
        return apReqTokenType;
    }

    protected void setApReqTokenType(ApReqTokenType apReqTokenType) {
        this.apReqTokenType = apReqTokenType;
    }
}
