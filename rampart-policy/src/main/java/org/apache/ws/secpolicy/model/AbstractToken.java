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

import org.apache.neethi.Constants;
import org.apache.neethi.Policy;
import org.apache.neethi.PolicyComponent;
import org.apache.neethi.PolicyContainingAssertion;
import org.apache.ws.secpolicy.SPConstants;
import org.apache.ws.secpolicy.SPUtils;
import org.w3c.dom.Element;

import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public abstract class AbstractToken extends AbstractSecurityAssertion implements PolicyContainingAssertion {

    public enum DerivedKeys {
        RequireDerivedKeys,
        RequireExplicitDerivedKeys,
        RequireImpliedDerivedKeys;

        private static final Map<String, X509Token.DerivedKeys> lookup = new HashMap<String, X509Token.DerivedKeys>();

        static {
            for (DerivedKeys u : EnumSet.allOf(DerivedKeys.class))
                lookup.put(u.name(), u);
        }

        public static DerivedKeys lookUp(String name) {
            return lookup.get(name);
        }
    }

    private SPConstants.IncludeTokenType includeTokenType;
    private Element issuer;
    private Element claims;
    private String issuerName;
    private DerivedKeys derivedKeys;
    private Policy nestedPolicy;
    private AbstractSecurityAssertion parentAssertion;

    protected AbstractToken(SPConstants.SPVersion version, SPConstants.IncludeTokenType includeTokenType,
                            Element issuer, String issuerName, Element claims, Policy nestedPolicy) {
        super(version);
        this.nestedPolicy = nestedPolicy;
        this.includeTokenType = includeTokenType;
        this.issuer = issuer;
        this.issuerName = issuerName;
        this.claims = claims;
    }

    public Policy getPolicy() {
        return nestedPolicy;
    }

    public PolicyComponent normalize() {
        return super.normalize(getPolicy());
    }

    public SPConstants.IncludeTokenType getIncludeTokenType() {
        return includeTokenType;
    }

    protected void setIncludeTokenType(SPConstants.IncludeTokenType includeTokenType) {
        this.includeTokenType = includeTokenType;
    }

    public Element getIssuer() {
        return issuer;
    }

    protected void setIssuer(Element issuer) {
        this.issuer = issuer;
    }

    public String getIssuerName() {
        return issuerName;
    }

    protected void setIssuerName(String issuerName) {
        this.issuerName = issuerName;
    }

    public Element getClaims() {
        return claims;
    }

    protected void setClaims(Element claims) {
        this.claims = claims;
    }

    public DerivedKeys getDerivedKeys() {
        return derivedKeys;
    }

    protected void setDerivedKeys(DerivedKeys derivedKeys) {
        this.derivedKeys = derivedKeys;
    }

    public AbstractSecurityAssertion getParentAssertion() {
        return parentAssertion;
    }

    public void setParentAssertion(AbstractSecurityAssertion parentAssertion) {
        this.parentAssertion = parentAssertion;
    }

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
            writer.writeAttribute(Constants.ATTR_WSP, writer.getNamespaceContext().getNamespaceURI(Constants.ATTR_WSP), Constants.ATTR_OPTIONAL, "true");
        }
        if (isIgnorable()) {
            writer.writeAttribute(Constants.ATTR_WSP, writer.getNamespaceContext().getNamespaceURI(Constants.ATTR_WSP), Constants.ATTR_IGNORABLE, "true");
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
        getPolicy().serialize(writer);
        writer.writeEndElement();
    }
}