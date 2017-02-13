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
import org.apache.wss4j.policy.SPConstants.SPVersion;
import org.w3c.dom.Element;

import javax.xml.namespace.QName;

import java.util.*;

public class X509Token extends AbstractToken {

    public enum TokenType {
        WssX509V1Token10,
        WssX509V3Token10,
        WssX509Pkcs7Token10,
        WssX509PkiPathV1Token10,
        WssX509V1Token11,
        WssX509V3Token11,
        WssX509Pkcs7Token11,
        WssX509PkiPathV1Token11;

        private static final Map<String, TokenType> LOOKUP = new HashMap<String, TokenType>();

        static {
            for (TokenType u : EnumSet.allOf(TokenType.class)) {
                LOOKUP.put(u.name(), u);
            }
        }

        public static TokenType lookUp(String name) {
            return LOOKUP.get(name);
        }
    }

    private boolean requireKeyIdentifierReference;
    private boolean requireIssuerSerialReference;
    private boolean requireEmbeddedTokenReference;
    private boolean requireThumbprintReference;

    private TokenType tokenType;

    public X509Token(SPConstants.SPVersion version, SPConstants.IncludeTokenType includeTokenType,
                     Element issuer, String issuerName, Element claims, Policy nestedPolicy) {
        super(version, includeTokenType, issuer, issuerName, claims, nestedPolicy);

        parseNestedPolicy(nestedPolicy, this);
    }

    @Override
    public QName getName() {
        return getVersion().getSPConstants().getX509Token();
    }

    @Override
    public boolean equals(Object object) {
        if (object == this) {
            return true;
        }
        if (!(object instanceof X509Token)) {
            return false;
        }

        X509Token that = (X509Token)object;
        if (tokenType != that.tokenType) {
            return false;
        }
        if (requireKeyIdentifierReference != that.requireKeyIdentifierReference
            || requireIssuerSerialReference != that.requireIssuerSerialReference
            || requireEmbeddedTokenReference != that.requireEmbeddedTokenReference
            || requireThumbprintReference != that.requireThumbprintReference) {
            return false;
        }

        return super.equals(object);
    }

    @Override
    public int hashCode() {
        int result = 17;
        if (tokenType != null) {
            result = 31 * result + tokenType.hashCode();
        }
        result = 31 * result + Boolean.hashCode(requireKeyIdentifierReference);
        result = 31 * result + Boolean.hashCode(requireIssuerSerialReference);
        result = 31 * result + Boolean.hashCode(requireEmbeddedTokenReference);
        result = 31 * result + Boolean.hashCode(requireThumbprintReference);

        return 31 * result + super.hashCode();
    }

    @Override
    protected AbstractSecurityAssertion cloneAssertion(Policy nestedPolicy) {
        return new X509Token(getVersion(), getIncludeTokenType(), getIssuer(), getIssuerName(),
                             getClaims(), nestedPolicy);
    }

    protected void parseNestedPolicy(Policy nestedPolicy, X509Token x509Token) {
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
                    if (x509Token.getDerivedKeys() != null) {
                        throw new IllegalArgumentException(SPConstants.ERR_INVALID_POLICY);
                    }
                    x509Token.setDerivedKeys(derivedKeys);
                    continue;
                }
                TokenType tokenType = TokenType.lookUp(assertionName);
                if (tokenType != null) {
                    if (x509Token.getTokenType() != null) {
                        throw new IllegalArgumentException(SPConstants.ERR_INVALID_POLICY);
                    }
                    if (TokenType.WssX509V1Token10 == tokenType && SPVersion.SP11 != getVersion()) {
                        throw new IllegalArgumentException(SPConstants.ERR_INVALID_POLICY);
                    }
                    x509Token.setTokenType(tokenType);
                    continue;
                }

                QName requireKeyIdentifierRef =
                    getVersion().getSPConstants().getRequireKeyIdentifierReference();
                QName requireIssuerSerialRef =
                    getVersion().getSPConstants().getRequireIssuerSerialReference();
                QName requireEmbeddedRef =
                    getVersion().getSPConstants().getRequireEmbeddedTokenReference();
                QName requireThumbprintRef =
                    getVersion().getSPConstants().getRequireThumbprintReference();
                if (requireKeyIdentifierRef.getLocalPart().equals(assertionName)
                    && requireKeyIdentifierRef.getNamespaceURI().equals(assertionNamespace)) {
                    if (x509Token.isRequireKeyIdentifierReference()) {
                        throw new IllegalArgumentException(SPConstants.ERR_INVALID_POLICY);
                    }
                    x509Token.setRequireKeyIdentifierReference(true);
                    continue;
                } else if (requireIssuerSerialRef.getLocalPart().equals(assertionName)
                        && requireIssuerSerialRef.getNamespaceURI().equals(assertionNamespace)) {
                    if (x509Token.isRequireIssuerSerialReference()) {
                        throw new IllegalArgumentException(SPConstants.ERR_INVALID_POLICY);
                    }
                    x509Token.setRequireIssuerSerialReference(true);
                    continue;
                } else if (requireEmbeddedRef.getLocalPart().equals(assertionName)
                        && requireEmbeddedRef.getNamespaceURI().equals(assertionNamespace)) {
                    if (x509Token.isRequireEmbeddedTokenReference()) {
                        throw new IllegalArgumentException(SPConstants.ERR_INVALID_POLICY);
                    }
                    x509Token.setRequireEmbeddedTokenReference(true);
                    continue;
                } else if (requireThumbprintRef.getLocalPart().equals(assertionName)
                        && requireThumbprintRef.getNamespaceURI().equals(assertionNamespace)) {
                    if (x509Token.isRequireThumbprintReference()) {
                        throw new IllegalArgumentException(SPConstants.ERR_INVALID_POLICY);
                    }
                    x509Token.setRequireThumbprintReference(true);
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

    public boolean isRequireIssuerSerialReference() {
        return requireIssuerSerialReference;
    }

    protected void setRequireIssuerSerialReference(boolean requireIssuerSerialReference) {
        this.requireIssuerSerialReference = requireIssuerSerialReference;
    }

    public boolean isRequireEmbeddedTokenReference() {
        return requireEmbeddedTokenReference;
    }

    protected void setRequireEmbeddedTokenReference(boolean requireEmbeddedTokenReference) {
        this.requireEmbeddedTokenReference = requireEmbeddedTokenReference;
    }

    public boolean isRequireThumbprintReference() {
        return requireThumbprintReference;
    }

    protected void setRequireThumbprintReference(boolean requireThumbprintReference) {
        this.requireThumbprintReference = requireThumbprintReference;
    }

    public TokenType getTokenType() {
        return tokenType;
    }

    protected void setTokenType(TokenType tokenType) {
        this.tokenType = tokenType;
    }
}
