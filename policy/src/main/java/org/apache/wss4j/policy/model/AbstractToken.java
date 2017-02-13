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

import org.apache.neethi.Constants;
import org.apache.neethi.Policy;
import org.apache.neethi.PolicyComponent;
import org.apache.neethi.PolicyContainingAssertion;
import org.apache.wss4j.policy.SPConstants;
import org.apache.wss4j.policy.SPUtils;
import org.w3c.dom.Element;

import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;

public abstract class AbstractToken extends AbstractSecurityAssertion implements PolicyContainingAssertion {

    public enum DerivedKeys {
        RequireDerivedKeys,
        RequireExplicitDerivedKeys,
        RequireImpliedDerivedKeys;

        private static final Map<String, DerivedKeys> LOOKUP = new HashMap<>();

        static {
            for (DerivedKeys u : EnumSet.allOf(DerivedKeys.class)) {
                LOOKUP.put(u.name(), u);
            }
        }

        public static DerivedKeys lookUp(String name) {
            return LOOKUP.get(name);
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

    @Override
    public Policy getPolicy() {
        return nestedPolicy;
    }

    @Override
    public PolicyComponent normalize() {
        return super.normalize(getPolicy());
    }

    @Override
    public boolean equals(Object object) {
        if (object == this) {
            return true;
        }
        if (!(object instanceof AbstractToken)) {
            return false;
        }

        AbstractToken that = (AbstractToken)object;
        if (includeTokenType != that.includeTokenType
            || derivedKeys != that.derivedKeys) {
            return false;
        }
        if (issuerName != null && !issuerName.equals(that.issuerName)
            || issuerName == null && that.issuerName != null) {
            return false;
        }

        if (issuer == null && that.issuer != null
            || issuer != null && issuer == null) {
            return false;
        }

        if (issuer != null
            && !DOM2Writer.nodeToString(issuer).equals(DOM2Writer.nodeToString(that.issuer))) {
            return false;
        }

        if (claims == null && that.claims != null
            || claims != null && claims == null) {
            return false;
        }

        if (claims != null
            && !DOM2Writer.nodeToString(claims).equals(DOM2Writer.nodeToString(that.claims))) {
            return false;
        }

        return super.equals(object);
    }

    @Override
    public int hashCode() {
        int result = 17;
        if (includeTokenType != null) {
            result = 31 * result + includeTokenType.hashCode();
        }
        if (derivedKeys != null) {
            result = 31 * result + derivedKeys.hashCode();
        }
        if (issuerName != null) {
            result = 31 * result + issuerName.hashCode();
        }

        if (issuer != null) {
            result = 31 * result + DOM2Writer.nodeToString(issuer).hashCode();
        }
        if (claims != null) {
            result = 31 * result + DOM2Writer.nodeToString(claims).hashCode();
        }

        return 31 * result + super.hashCode();
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
        getPolicy().serialize(writer);
        writer.writeEndElement();
    }
}