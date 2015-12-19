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

        private static final Map<String, TokenType> lookup = new HashMap<String, TokenType>();

        static {
            for (TokenType u : EnumSet.allOf(TokenType.class))
                lookup.put(u.name(), u);
        }

        public static TokenType lookUp(String name) {
            return lookup.get(name);
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
    protected AbstractSecurityAssertion cloneAssertion(Policy nestedPolicy) {
        return new X509Token(getVersion(), getIncludeTokenType(), getIssuer(), getIssuerName(), getClaims(), nestedPolicy);
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
                if (getVersion().getSPConstants().getRequireKeyIdentifierReference().getLocalPart().equals(assertionName)
                        && getVersion().getSPConstants().getRequireKeyIdentifierReference().getNamespaceURI().equals(assertionNamespace)) {
                    if (x509Token.isRequireKeyIdentifierReference()) {
                        throw new IllegalArgumentException(SPConstants.ERR_INVALID_POLICY);
                    }
                    x509Token.setRequireKeyIdentifierReference(true);
                    continue;
                } else if (getVersion().getSPConstants().getRequireIssuerSerialReference().getLocalPart().equals(assertionName)
                        && getVersion().getSPConstants().getRequireIssuerSerialReference().getNamespaceURI().equals(assertionNamespace)) {
                    if (x509Token.isRequireIssuerSerialReference()) {
                        throw new IllegalArgumentException(SPConstants.ERR_INVALID_POLICY);
                    }
                    x509Token.setRequireIssuerSerialReference(true);
                    continue;
                } else if (getVersion().getSPConstants().getRequireEmbeddedTokenReference().getLocalPart().equals(assertionName)
                        && getVersion().getSPConstants().getRequireEmbeddedTokenReference().getNamespaceURI().equals(assertionNamespace)) {
                    if (x509Token.isRequireEmbeddedTokenReference()) {
                        throw new IllegalArgumentException(SPConstants.ERR_INVALID_POLICY);
                    }
                    x509Token.setRequireEmbeddedTokenReference(true);
                    continue;
                } else if (getVersion().getSPConstants().getRequireThumbprintReference().getLocalPart().equals(assertionName)
                        && getVersion().getSPConstants().getRequireThumbprintReference().getNamespaceURI().equals(assertionNamespace)) {
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
