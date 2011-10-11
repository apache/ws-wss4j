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
import org.swssf.policy.OperationPolicy;
import org.swssf.policy.assertionStates.AssertionState;
import org.swssf.policy.secpolicy.SPConstants;
import org.swssf.wss.securityEvent.SecurityEvent;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;
import java.util.List;
import java.util.Map;

/**
 * class lent from apache cxf
 */
public class SamlToken extends Token {

    private boolean useSamlVersion11Profile10;
    private boolean useSamlVersion11Profile11;
    private boolean useSamlVersion20Profile11;
    private boolean requireKeyIdentifierReference;

    public SamlToken(SPConstants spConstants) {
        setVersion(spConstants);
    }

    public boolean isUseSamlVersion11Profile10() {
        return useSamlVersion11Profile10;
    }

    public void setUseSamlVersion11Profile10(boolean useSamlVersion11Profile10) {
        this.useSamlVersion11Profile10 = useSamlVersion11Profile10;
    }

    public boolean isUseSamlVersion11Profile11() {
        return useSamlVersion11Profile11;
    }

    public void setUseSamlVersion11Profile11(boolean useSamlVersion11Profile11) {
        this.useSamlVersion11Profile11 = useSamlVersion11Profile11;
    }

    public boolean isUseSamlVersion20Profile11() {
        return useSamlVersion20Profile11;
    }

    public void setUseSamlVersion20Profile11(boolean useSamlVersion20Profile11) {
        this.useSamlVersion20Profile11 = useSamlVersion20Profile11;
    }

    public boolean isRequireKeyIdentifierReference() {
        return requireKeyIdentifierReference;
    }

    public void setRequireKeyIdentifierReference(boolean requireKeyIdentifierReference) {
        this.requireKeyIdentifierReference = requireKeyIdentifierReference;
    }

    public QName getName() {
        return spConstants.getSamlToken();
    }

    public void serialize(XMLStreamWriter writer) throws XMLStreamException {
        String localname = getName().getLocalPart();
        String namespaceURI = getName().getNamespaceURI();

        String prefix = writer.getPrefix(namespaceURI);
        if (prefix == null) {
            prefix = getName().getPrefix();
            writer.setPrefix(prefix, namespaceURI);
        }

        // <sp:SamlToken
        writer.writeStartElement(prefix, localname, namespaceURI);

        writer.writeNamespace(prefix, namespaceURI);

        String inclusion;

        inclusion = spConstants.getAttributeValueFromInclusion(getInclusion());

        if (inclusion != null) {
            writer.writeAttribute(prefix, namespaceURI, SPConstants.ATTR_INCLUDE_TOKEN, inclusion);
        }

        if (isUseSamlVersion11Profile10() || isUseSamlVersion11Profile11()
                || isUseSamlVersion20Profile11()) {
            String pPrefix = writer.getPrefix(SPConstants.POLICY.getNamespaceURI());
            if (pPrefix == null) {
                pPrefix = SPConstants.POLICY.getPrefix();
                writer.setPrefix(SPConstants.POLICY.getPrefix(), SPConstants.POLICY.getNamespaceURI());
            }

            // <wsp:Policy>
            writer.writeStartElement(pPrefix, SPConstants.POLICY.getLocalPart(), SPConstants.POLICY
                    .getNamespaceURI());

            // CHECKME
            if (isUseSamlVersion11Profile10()) {
                // <sp:WssSamlV11Token10 />
                writer.writeStartElement(prefix, SPConstants.SAML_11_TOKEN_10, namespaceURI);
            } else if (isUseSamlVersion11Profile11()) {
                // <sp:WssSamlV11Token11 />
                writer.writeStartElement(prefix, SPConstants.SAML_11_TOKEN_11, namespaceURI);
            } else {
                // <sp:WssSamlV20Token11 />
                writer.writeStartElement(prefix, SPConstants.SAML_20_TOKEN_11, namespaceURI);
            }

            writer.writeEndElement();

            // </wsp:Policy>
            writer.writeEndElement();

        }

        writer.writeEndElement();
        // </sp:SamlToken>

    }

    @Override
    public QName getXmlName() {
        return null;
    }

    @Override
    public void getAssertions(Map<SecurityEvent.Event, Map<Assertion, List<AssertionState>>> assertionStateMap, OperationPolicy operationPolicy) {
        //todo
    }
}
