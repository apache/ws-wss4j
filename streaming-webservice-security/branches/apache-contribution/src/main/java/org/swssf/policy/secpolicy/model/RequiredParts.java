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
import org.swssf.policy.OperationPolicy;
import org.swssf.policy.assertionStates.AssertionState;
import org.swssf.policy.assertionStates.RequiredPartAssertionState;
import org.swssf.policy.secpolicy.SP12Constants;
import org.swssf.policy.secpolicy.SPConstants;
import org.swssf.securityEvent.SecurityEvent;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/**
 * class lent from apache rampart
 */
public class RequiredParts extends AbstractSecurityAssertion {

    private List<Header> headers = new ArrayList<Header>();

    public RequiredParts(SPConstants spConstants) {
        setVersion(spConstants);
    }

    /**
     * @return Returns the headers.
     */
    public List<Header> getHeaders() {
        return this.headers;
    }

    /**
     * @param header The headers to set.
     */
    public void addHeader(Header header) {
        this.headers.add(header);
    }


    public QName getName() {
        return SP12Constants.REQUIRED_PARTS;
    }

    public PolicyComponent normalize() {
        return this;
    }

    public void serialize(XMLStreamWriter writer) throws XMLStreamException {
        String localName = getName().getLocalPart();
        String namespaceURI = getName().getNamespaceURI();

        String prefix = writer.getPrefix(namespaceURI);

        if (prefix == null) {
            prefix = getName().getPrefix();
            writer.setPrefix(prefix, namespaceURI);
        }

        // <sp:RequiredParts> 
        writer.writeStartElement(prefix, localName, namespaceURI);

        // xmlns:sp=".."
        writer.writeNamespace(prefix, namespaceURI);

        Header header;
        for (Iterator iterator = headers.iterator(); iterator.hasNext(); ) {
            header = (Header) iterator.next();
            // <sp:Header Name=".." Namespace=".." />
            writer.writeStartElement(prefix, SPConstants.HEADER, namespaceURI);
            // Name attribute is optional
            if (header.getName() != null) {
                writer.writeAttribute("Name", header.getName());
            }
            writer.writeAttribute("Namespace", header.getNamespace());

            writer.writeEndElement();
        }

        // </sp:RequiredParts>
        writer.writeEndElement();
    }

    @Override
    public SecurityEvent.Event[] getResponsibleAssertionEvents() {
        return new SecurityEvent.Event[]{SecurityEvent.Event.RequiredPart};
    }

    @Override
    public void getAssertions(Map<SecurityEvent.Event, Map<Assertion, List<AssertionState>>> assertionStateMap, OperationPolicy operationPolicy) {
        Map<Assertion, List<AssertionState>> requiredPartsAssertionStates = assertionStateMap.get(SecurityEvent.Event.RequiredPart);
        List<QName> qNames = getQNamesFromHeaders();
        for (int i = 0; i < qNames.size(); i++) {
            QName qName = qNames.get(i);
            addAssertionState(requiredPartsAssertionStates, this, new RequiredPartAssertionState(this, false, qName));
        }
    }

    private List<QName> getQNamesFromHeaders() {
        List<QName> qNames = new ArrayList<QName>(headers.size());
        for (int i = 0; i < headers.size(); i++) {
            Header header = headers.get(i);
            String localName = header.getName();
            if (localName == null) {
                localName = "*";
            }
            qNames.add(new QName(header.getNamespace(), localName));
        }
        return qNames;
    }
}
