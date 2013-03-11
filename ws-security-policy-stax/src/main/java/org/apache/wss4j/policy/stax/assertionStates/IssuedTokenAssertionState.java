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

import org.apache.wss4j.common.saml.SamlAssertionWrapper;
import org.apache.wss4j.policy.WSSPolicyException;
import org.apache.wss4j.policy.model.AbstractSecurityAssertion;
import org.apache.wss4j.policy.model.AbstractToken;
import org.apache.wss4j.policy.model.IssuedToken;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.securityEvent.KerberosTokenSecurityEvent;
import org.apache.wss4j.stax.securityEvent.SamlTokenSecurityEvent;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.securityEvent.SecurityEventConstants;
import org.apache.xml.security.stax.securityEvent.TokenSecurityEvent;
import org.apache.wss4j.stax.securityEvent.IssuedTokenSecurityEvent;
import org.apache.wss4j.stax.securityEvent.WSSecurityEventConstants;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.AttributeStatement;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import java.net.URI;
import java.security.Key;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;

/**
 * WSP1.3, 5.4.2 IssuedToken Assertion
 */

public class IssuedTokenAssertionState extends TokenAssertionState {

    public IssuedTokenAssertionState(AbstractSecurityAssertion assertion, boolean asserted) {
        super(assertion, asserted);
    }

    @Override
    public SecurityEventConstants.Event[] getSecurityEventType() {
        return new SecurityEventConstants.Event[]{
                WSSecurityEventConstants.KerberosToken,
                WSSecurityEventConstants.RelToken,
                WSSecurityEventConstants.SamlToken,
                WSSecurityEventConstants.SecurityContextToken,
        };
    }

    @Override
    public boolean assertToken(TokenSecurityEvent tokenSecurityEvent, AbstractToken abstractToken) throws WSSPolicyException {
        if (!(tokenSecurityEvent instanceof IssuedTokenSecurityEvent)) {
            throw new WSSPolicyException("Expected a IssuedTokenSecurityEvent but got " + tokenSecurityEvent.getClass().getName());
        }

        IssuedToken issuedToken = (IssuedToken) abstractToken;
        IssuedTokenSecurityEvent issuedTokenSecurityEvent = (IssuedTokenSecurityEvent) tokenSecurityEvent;
        if ((issuedToken.getIssuerName() != null) &&
                !issuedToken.getIssuerName().equals(issuedTokenSecurityEvent.getIssuerName())) {
            setErrorMessage("IssuerName in Policy (" + issuedToken.getIssuerName() + ") didn't match with the one in the IssuedToken (" + issuedTokenSecurityEvent.getIssuerName() + ")");
            return false;
        }
        if (issuedToken.getRequestSecurityTokenTemplate() != null) {
            if (issuedTokenSecurityEvent instanceof SamlTokenSecurityEvent) {
                SamlTokenSecurityEvent samlTokenSecurityEvent = (SamlTokenSecurityEvent) issuedTokenSecurityEvent;
                try {
                    String errorMsg = checkIssuedTokenTemplate(issuedToken.getRequestSecurityTokenTemplate(), samlTokenSecurityEvent);
                    if (errorMsg != null) {
                        setErrorMessage(errorMsg);
                        return false;
                    }
                } catch (XMLSecurityException e) {
                    throw new WSSPolicyException(e.getMessage(), e);
                }
            } else if (issuedTokenSecurityEvent instanceof KerberosTokenSecurityEvent) {
                KerberosTokenSecurityEvent kerberosTokenSecurityEvent = (KerberosTokenSecurityEvent) issuedTokenSecurityEvent;
                String errorMsg = checkIssuedTokenTemplate(issuedToken.getRequestSecurityTokenTemplate(), kerberosTokenSecurityEvent);
                if (errorMsg != null) {
                    setErrorMessage(errorMsg);
                    return false;
                }
            }
        }

        //always return true to prevent false alarm in case additional tokens with the same usage
        //appears in the message but do not fulfill the policy and are also not needed to fulfil the policy.
        return true;
    }

    /**
     * Check the issued token template against the received assertion
     */
    protected String checkIssuedTokenTemplate(Element template, SamlTokenSecurityEvent samlTokenSecurityEvent) throws XMLSecurityException {
        Node child = template.getFirstChild();
        while (child != null) {
            if (child.getNodeType() != Node.ELEMENT_NODE) {
                child = child.getNextSibling();
                continue;
            }
            if ("TokenType".equals(child.getLocalName())) {
                String content = child.getTextContent();
                if (WSSConstants.NS_SAML11_TOKEN_PROFILE_TYPE.equals(content)
                        && samlTokenSecurityEvent.getSamlVersion() != SAMLVersion.VERSION_11) {
                    return "Policy enforces SAML V1.1 token but got " + samlTokenSecurityEvent.getSamlVersion().toString();
                } else if (WSSConstants.NS_SAML20_TOKEN_PROFILE_TYPE.equals(content)
                        && samlTokenSecurityEvent.getSamlVersion() != SAMLVersion.VERSION_20) {
                    return "Policy enforces SAML V2.0 token but got " + samlTokenSecurityEvent.getSamlVersion().toString();
                }
            } else if ("KeyType".equals(child.getLocalName())) {
                String content = child.getTextContent();
                if (content.endsWith("SymmetricKey")) {
                    Map<String, Key> subjectKeys = samlTokenSecurityEvent.getSecurityToken().getSecretKey();
                    if (subjectKeys.isEmpty()) {
                        return "Policy enforces SAML token with a symmetric key";
                    }
                } else if (content.endsWith("PublicKey")) {
                    PublicKey publicKey = samlTokenSecurityEvent.getSecurityToken().getPublicKey();
                    X509Certificate[] x509Certificate = samlTokenSecurityEvent.getSecurityToken().getX509Certificates();
                    if (publicKey == null && x509Certificate == null) {
                        return "Policy enforces SAML token with an asymmetric key";
                    }
                }
            } else if ("Claims".equals(child.getLocalName())) {
                String errorMsg = validateClaims((Element) child, samlTokenSecurityEvent);
                if (errorMsg != null) {
                    return errorMsg;
                }
            }
            child = child.getNextSibling();
        }
        return null;
    }

    /**
     * Check the issued token template against the received BinarySecurityToken
     */
    private String checkIssuedTokenTemplate(Element template, KerberosTokenSecurityEvent kerberosTokenSecurityEvent) {
        Node child = template.getFirstChild();
        while (child != null) {
            if (child.getNodeType() != Node.ELEMENT_NODE) {
                child = child.getNextSibling();
                continue;
            }
            if ("TokenType".equals(child.getLocalName())) {
                String content = child.getTextContent();
                String valueType = kerberosTokenSecurityEvent.getKerberosTokenValueType();
                if (!content.equals(valueType)) {
                    return "Policy enforces Kerberos token of type " + content + " but got " + valueType;
                }
            }
            child = child.getNextSibling();
        }
        return null;
    }

    //todo I think the best is if we allow to set custom AssertionStates object on the policy-engine for
    //custom validation -> task for WSS4j V2.1 ?
    protected String validateClaims(Element claimsPolicy, SamlTokenSecurityEvent samlTokenSecurityEvent) {
        Node child = claimsPolicy.getFirstChild();
        while (child != null) {
            if (child.getNodeType() != Node.ELEMENT_NODE) {
                child = child.getNextSibling();
                continue;
            }

            String dialect = claimsPolicy.getAttributeNS(null, "Dialect");
            if (!"http://schemas.xmlsoap.org/ws/2005/05/identity".equals(dialect)) {
                return "Unsupported claims dialect: " + dialect;
            }
            if ("ClaimType".equals(child.getLocalName())) {
                Element claimType = (Element) child;
                String claimTypeUri = claimType.getAttributeNS(null, "Uri");
                String claimTypeOptional = claimType.getAttributeNS(null, "Optional");

                if ("".equals(claimTypeOptional) || !Boolean.parseBoolean(claimTypeOptional)) {
                    String errorMsg = findClaimInAssertion(samlTokenSecurityEvent.getSamlAssertionWrapper(), URI.create(claimTypeUri));
                    if (errorMsg != null) {
                        return errorMsg;
                    }
                }
            }
            child = child.getNextSibling();
        }
        return null;
    }

    protected String findClaimInAssertion(SamlAssertionWrapper samlAssertionWrapper, URI claimURI) {
        if (samlAssertionWrapper.getSaml1() != null) {
            return findClaimInAssertion(samlAssertionWrapper.getSaml1(), claimURI);
        } else if (samlAssertionWrapper.getSaml2() != null) {
            return findClaimInAssertion(samlAssertionWrapper.getSaml2(), claimURI);
        }
        return "Unsupported SAML version";
    }

    protected String findClaimInAssertion(org.opensaml.saml2.core.Assertion assertion, URI claimURI) {
        List<AttributeStatement> attributeStatements =
                assertion.getAttributeStatements();
        if (attributeStatements == null || attributeStatements.isEmpty()) {
            return "Attribute " + claimURI + " not found in the SAMLAssertion";
        }

        for (org.opensaml.saml2.core.AttributeStatement statement : attributeStatements) {
            List<org.opensaml.saml2.core.Attribute> attributes = statement.getAttributes();
            for (org.opensaml.saml2.core.Attribute attribute : attributes) {

                if (attribute.getName().equals(claimURI.toString())
                        && attribute.getAttributeValues() != null && !attribute.getAttributeValues().isEmpty()) {
                    return null;
                }
            }
        }
        return "Attribute " + claimURI + " not found in the SAMLAssertion";
    }

    protected String findClaimInAssertion(org.opensaml.saml1.core.Assertion assertion, URI claimURI) {
        List<org.opensaml.saml1.core.AttributeStatement> attributeStatements =
                assertion.getAttributeStatements();
        if (attributeStatements == null || attributeStatements.isEmpty()) {
            return "Attribute " + claimURI + " not found in the SAMLAssertion";
        }

        for (org.opensaml.saml1.core.AttributeStatement statement : attributeStatements) {

            List<org.opensaml.saml1.core.Attribute> attributes = statement.getAttributes();
            for (org.opensaml.saml1.core.Attribute attribute : attributes) {

                URI attributeNamespace = URI.create(attribute.getAttributeNamespace());
                String desiredRole = attributeNamespace.relativize(claimURI).toString();
                if (attribute.getAttributeName().equals(desiredRole)
                        && attribute.getAttributeValues() != null && !attribute.getAttributeValues().isEmpty()) {
                    return null;
                }
            }
        }
        return "Attribute " + claimURI + " not found in the SAMLAssertion";
    }
}
