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

package org.swssf.policy.secpolicy.model;

import org.apache.neethi.Assertion;
import org.apache.neethi.PolicyComponent;
import org.swssf.ext.Constants;
import org.swssf.policy.OperationPolicy;
import org.swssf.policy.assertionStates.AssertionState;
import org.swssf.policy.assertionStates.TokenAssertionState;
import org.swssf.policy.secpolicy.SPConstants;
import org.swssf.securityEvent.SecurityEvent;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;
import java.util.List;
import java.util.Map;

/**
 * class lent from apache rampart
 */
public class UsernameToken extends Token {

    private boolean useUTProfile10 = false;

    private boolean useUTProfile11 = false;

    private boolean noPassword;

    private boolean hashPassword;

    private boolean createdTimestamp;

    private boolean nonce;

    public UsernameToken(SPConstants spConstants) {
        setVersion(spConstants);
    }

    /**
     * @return Returns the useUTProfile11.
     */
    public boolean isUseUTProfile11() {
        return useUTProfile11;
    }

    /**
     * @param useUTProfile11 The useUTProfile11 to set.
     */
    public void setUseUTProfile11(boolean useUTProfile11) {
        this.useUTProfile11 = useUTProfile11;
    }

    public boolean isNoPassword() {
        return noPassword;
    }

    public void setNoPassword(boolean noPassword) {
        this.noPassword = noPassword;
    }

    public boolean isHashPassword() {
        return hashPassword;
    }

    public void setHashPassword(boolean hashPassword) {
        this.hashPassword = hashPassword;
    }

    public boolean isUseUTProfile10() {
        return useUTProfile10;
    }

    public void setUseUTProfile10(boolean useUTProfile10) {
        this.useUTProfile10 = useUTProfile10;
    }

    public boolean isCreatedTimestamp() {
        return createdTimestamp;
    }

    public void setCreatedTimestamp(boolean createdTimestamp) {
        this.createdTimestamp = createdTimestamp;
    }

    public boolean isNonce() {
        return nonce;
    }

    public void setNonce(boolean nonce) {
        this.nonce = nonce;
    }

    public QName getName() {
        return spConstants.getUserNameToken();
    }

    public PolicyComponent normalize() {
        throw new UnsupportedOperationException();
    }

    public void serialize(XMLStreamWriter writer) throws XMLStreamException {
        String localname = getName().getLocalPart();
        String namespaceURI = getName().getNamespaceURI();

        String prefix = writer.getPrefix(namespaceURI);
        if (prefix == null) {
            prefix = getName().getPrefix();
            writer.setPrefix(prefix, namespaceURI);
        }

        // <sp:UsernameToken
        writer.writeStartElement(prefix, localname, namespaceURI);

        writer.writeNamespace(prefix, namespaceURI);

        String inclusion = spConstants.getAttributeValueFromInclusion(getInclusion());

        if (inclusion != null) {
            writer.writeAttribute(prefix, namespaceURI, SPConstants.ATTR_INCLUDE_TOKEN, inclusion);
        }

        if (isUseUTProfile10() || isUseUTProfile11()) {
            String pPrefix = writer.getPrefix(SPConstants.POLICY
                    .getNamespaceURI());
            if (pPrefix == null) {
                writer.setPrefix(SPConstants.POLICY.getPrefix(), SPConstants.POLICY
                        .getNamespaceURI());
            }

            // <wsp:Policy>
            writer.writeStartElement(prefix, SPConstants.POLICY.getLocalPart(),
                    SPConstants.POLICY.getNamespaceURI());

            // CHECKME
            if (isUseUTProfile10()) {
                // <sp:WssUsernameToken10 />
                writer.writeStartElement(prefix, SPConstants.USERNAME_TOKEN10, namespaceURI);
            } else {
                // <sp:WssUsernameToken11 />
                writer.writeStartElement(prefix, SPConstants.USERNAME_TOKEN11, namespaceURI);
            }

            if (spConstants.getVersion() == SPConstants.Version.SP_V12) {

                if (isNoPassword()) {
                    writer.writeStartElement(prefix, SPConstants.NO_PASSWORD, namespaceURI);
                    writer.writeEndElement();
                } else if (isHashPassword()) {
                    writer.writeStartElement(prefix, SPConstants.HASH_PASSWORD, namespaceURI);
                    writer.writeEndElement();
                }

                if (isDerivedKeys()) {
                    writer.writeStartElement(prefix, SPConstants.REQUIRE_DERIVED_KEYS, namespaceURI);
                    writer.writeEndElement();
                } else if (isExplicitDerivedKeys()) {
                    writer.writeStartElement(prefix, SPConstants.REQUIRE_EXPLICIT_DERIVED_KEYS, namespaceURI);
                    writer.writeEndElement();
                } else if (isImpliedDerivedKeys()) {
                    writer.writeStartElement(prefix, SPConstants.REQUIRE_IMPLIED_DERIVED_KEYS, namespaceURI);
                    writer.writeEndElement();
                }

            }
            writer.writeEndElement();

            // </wsp:Policy>
            writer.writeEndElement();

        }

        writer.writeEndElement();
        // </sp:UsernameToken>

    }

    public QName getXmlName() {
        return Constants.TAG_wsse_UsernameToken;
    }

    @Override
    public SecurityEvent.Event[] getResponsibleAssertionEvents() {
        return new SecurityEvent.Event[]{SecurityEvent.Event.UsernameToken};
    }

    @Override
    public void getAssertions(Map<SecurityEvent.Event, Map<Assertion, List<AssertionState>>> assertionStateMap, OperationPolicy operationPolicy) {
        SecurityEvent.Event[] responsibleAssertionEvents = getResponsibleAssertionEvents();
        for (int i = 0; i < responsibleAssertionEvents.length; i++) {
            SecurityEvent.Event responsibleAssertionEvent = responsibleAssertionEvents[i];
            Map<Assertion, List<AssertionState>> assertionStates = assertionStateMap.get(responsibleAssertionEvent);
            TokenAssertionState tokenAssertionState = new TokenAssertionState(this, false);
            addAssertionState(assertionStates, this, tokenAssertionState);
        }
    }
}
