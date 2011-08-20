/*
 * Copyright 2004,2005 The Apache Software Foundation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.swssf.policy.secpolicy.model;

import org.apache.neethi.Assertion;
import org.apache.neethi.PolicyComponent;
import org.swssf.ext.Constants;
import org.swssf.policy.OperationPolicy;
import org.swssf.policy.assertionStates.AssertionState;
import org.swssf.policy.assertionStates.EncryptedPartAssertionState;
import org.swssf.policy.assertionStates.SignedPartAssertionState;
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
public class SignedEncryptedParts extends AbstractSecurityAssertion {

    private boolean body;

    private boolean attachments;

    private List<Header> headers = new ArrayList<Header>();

    private boolean signedParts;

    public SignedEncryptedParts(boolean signedParts, SPConstants spConstants) {
        this.signedParts = signedParts;
        setVersion(spConstants);
    }

    /**
     * @return Returns the body.
     */
    public boolean isBody() {
        return body;
    }

    /**
     * @param body The body to set.
     */
    public void setBody(boolean body) {
        this.body = body;
    }

    /**
     * @return Returns the attachments.
     */
    public boolean isAttachments() {
        return attachments;
    }

    /**
     * @param attachments The attachments to set.
     */
    public void setAttachments(boolean attachments) {
        this.attachments = attachments;
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

    /**
     * @return Returns the signedParts.
     */
    public boolean isSignedParts() {
        return signedParts;
    }

    public QName getName() {
        if (signedParts) {
            return spConstants.getSignedParts();
        }
        return spConstants.getEncryptedParts();
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

        // <sp:SignedParts> | <sp:EncryptedParts> 
        writer.writeStartElement(prefix, localName, namespaceURI);

        // xmlns:sp=".."
        writer.writeNamespace(prefix, namespaceURI);

        if (isBody()) {
            // <sp:Body />
            writer.writeStartElement(prefix, SPConstants.BODY, namespaceURI);
            writer.writeEndElement();
        }

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

        if (isAttachments() && spConstants.getVersion() == SPConstants.Version.SP_V12) {
            // <sp:Attachments />
            writer.writeStartElement(prefix, SPConstants.ATTACHMENTS, namespaceURI);
            writer.writeEndElement();
        }

        // </sp:SignedParts> | </sp:EncryptedParts>
        writer.writeEndElement();
    }

    @Override
    public SecurityEvent.Event[] getResponsibleAssertionEvents() {
        if (isSignedParts()) {
            return new SecurityEvent.Event[]{SecurityEvent.Event.SignedPart};
        } else {
            return new SecurityEvent.Event[]{SecurityEvent.Event.EncryptedPart};
        }
    }

    @Override
    public void getAssertions(Map<SecurityEvent.Event, Map<Assertion, List<AssertionState>>> assertionStateMap, OperationPolicy operationPolicy) {
        //here we add just one AssertionState for all Parts to get a fail-fast behavior
        //when we add multiple AssertionStates some of them return true, becauce they don't match
        //as a result the policy is temporary satisfied for the current event and can only be falsified at last 
        if (isSignedParts()) {
            Map<Assertion, List<AssertionState>> signedPartsAssertionStates = assertionStateMap.get(SecurityEvent.Event.SignedPart);
            List<QName> qNames = getQNamesFromHeaders();
            if (isBody()) {
                qNames.add(new QName(operationPolicy.getSoapMessageVersionNamespace(), Constants.TAG_soap_Body_LocalName));
            }
            addAssertionState(signedPartsAssertionStates, this, new SignedPartAssertionState(this, true, qNames));
        } else {
            Map<Assertion, List<AssertionState>> encryptedPartsAssertionStates = assertionStateMap.get(SecurityEvent.Event.EncryptedPart);
            List<QName> qNames = getQNamesFromHeaders();
            if (isBody()) {
                qNames.add(new QName(operationPolicy.getSoapMessageVersionNamespace(), Constants.TAG_soap_Body_LocalName));
            }
            addAssertionState(encryptedPartsAssertionStates, this, new EncryptedPartAssertionState(this, true, qNames));
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
