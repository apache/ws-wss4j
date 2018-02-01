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
import org.apache.neethi.Constants;
import org.apache.neethi.Policy;
import org.apache.wss4j.policy.SPConstants;
import org.apache.wss4j.policy.SPUtils;
import org.w3c.dom.Element;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;
import java.util.Iterator;
import java.util.List;

public class IssuedToken extends AbstractToken {

    private Element requestSecurityTokenTemplate;
    private boolean requireExternalReference;
    private boolean requireInternalReference;

    public IssuedToken(SPConstants.SPVersion version, SPConstants.IncludeTokenType includeTokenType,
                       Element issuer, String issuerName, Element requestSecurityTokenTemplate, Element claims,
                       Policy nestedPolicy) {
        super(version, includeTokenType, issuer, issuerName, claims, nestedPolicy);
        setRequestSecurityTokenTemplate(requestSecurityTokenTemplate);

        parseNestedPolicy(nestedPolicy, this);
    }

    @Override
    public QName getName() {
        return getVersion().getSPConstants().getIssuedToken();
    }

    @Override
    public boolean equals(Object object) {
        if (object == this) {
            return true;
        }
        if (!(object instanceof IssuedToken)) {
            return false;
        }

        IssuedToken that = (IssuedToken)object;
        if (requireExternalReference != that.requireExternalReference
            || requireInternalReference != that.requireInternalReference) {
            return false;
        }

        if (requestSecurityTokenTemplate == null && that.requestSecurityTokenTemplate != null
            || requestSecurityTokenTemplate != null && requestSecurityTokenTemplate == null) {
            return false;
        }

        if (requestSecurityTokenTemplate != null
            && !DOM2Writer.nodeToString(requestSecurityTokenTemplate).equals(
                DOM2Writer.nodeToString(that.requestSecurityTokenTemplate))) {
            return false;
        }

        return super.equals(object);
    }

    @Override
    public int hashCode() {
        int result = 17;
        if (requestSecurityTokenTemplate != null) {
            result = 31 * result + DOM2Writer.nodeToString(requestSecurityTokenTemplate).hashCode();
        }
        result = 31 * result + Boolean.hashCode(requireExternalReference);
        result = 31 * result + Boolean.hashCode(requireInternalReference);

        return 31 * result + super.hashCode();
    }

    @Override
    public void serialize(XMLStreamWriter writer) throws XMLStreamException {
        writer.writeStartElement(getName().getPrefix(), getName().getLocalPart(), getName().getNamespaceURI());
        writer.writeNamespace(getName().getPrefix(), getName().getNamespaceURI());
        if (getIncludeTokenType() != null) {
            writer.writeAttribute(
                    getVersion().getSPConstants().getIncludeToken().getPrefix(),
                    getVersion().getSPConstants().getIncludeToken().getNamespaceURI(),
                    getVersion().getSPConstants().getIncludeToken().getLocalPart(),
                    getVersion().getSPConstants().getAttributeValueFromInclusion(getIncludeTokenType())
            );
        }
        if (!isNormalized() && isOptional()) {
            writer.writeAttribute(Constants.ATTR_WSP,
                                  writer.getNamespaceContext().getNamespaceURI(Constants.ATTR_WSP),
                                  Constants.ATTR_OPTIONAL, "true");
        }
        if (isIgnorable()) {
            writer.writeAttribute(Constants.ATTR_WSP,
                                  writer.getNamespaceContext().getNamespaceURI(Constants.ATTR_WSP),
                                  Constants.ATTR_IGNORABLE, "true");
        }
        if (getIssuer() != null) {
            SPUtils.serialize(getIssuer(), writer);
        }
        if (getIssuerName() != null) {
            writer.writeStartElement(
                    getVersion().getSPConstants().getIssuerName().getPrefix(),
                    getVersion().getSPConstants().getIssuerName().getLocalPart(),
                    getVersion().getSPConstants().getIssuerName().getNamespaceURI()
            );
            writer.writeCharacters(getIssuerName());
            writer.writeEndElement();
        }
        if (getClaims() != null) {
            SPUtils.serialize(getClaims(), writer);
        }
        SPUtils.serialize(getRequestSecurityTokenTemplate(), writer);
        getPolicy().serialize(writer);
        writer.writeEndElement();
    }

    @Override
    protected AbstractSecurityAssertion cloneAssertion(Policy nestedPolicy) {
        return new IssuedToken(getVersion(), getIncludeTokenType(), getIssuer(), getIssuerName(),
                getRequestSecurityTokenTemplate(), getClaims(), nestedPolicy);
    }

    protected void parseNestedPolicy(Policy nestedPolicy, IssuedToken issuedToken) {
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
                    if (issuedToken.getDerivedKeys() != null) {
                        throw new IllegalArgumentException(SPConstants.ERR_INVALID_POLICY);
                    }
                    issuedToken.setDerivedKeys(derivedKeys);
                    continue;
                }

                QName requireExternalRef = getVersion().getSPConstants().getRequireExternalReference();
                if (requireExternalRef.getLocalPart().equals(assertionName)
                    && requireExternalRef.getNamespaceURI().equals(assertionNamespace)) {
                    if (issuedToken.isRequireExternalReference()) {
                        throw new IllegalArgumentException(SPConstants.ERR_INVALID_POLICY);
                    }
                    issuedToken.setRequireExternalReference(true);
                    continue;
                }

                QName requireInternalRef = getVersion().getSPConstants().getRequireInternalReference();
                if (requireInternalRef.getLocalPart().equals(assertionName)
                    && requireInternalRef.getNamespaceURI().equals(assertionNamespace)) {
                    if (issuedToken.isRequireInternalReference()) {
                        throw new IllegalArgumentException(SPConstants.ERR_INVALID_POLICY);
                    }
                    issuedToken.setRequireInternalReference(true);
                    continue;
                }
            }
        }
    }

    public boolean isRequireExternalReference() {
        return requireExternalReference;
    }

    protected void setRequireExternalReference(boolean requireExternalReference) {
        this.requireExternalReference = requireExternalReference;
    }

    public boolean isRequireInternalReference() {
        return requireInternalReference;
    }

    protected void setRequireInternalReference(boolean requireInternalReference) {
        this.requireInternalReference = requireInternalReference;
    }

    public Element getRequestSecurityTokenTemplate() {
        return requestSecurityTokenTemplate;
    }

    protected void setRequestSecurityTokenTemplate(Element requestSecurityTokenTemplate) {
        this.requestSecurityTokenTemplate = requestSecurityTokenTemplate;
    }
}
