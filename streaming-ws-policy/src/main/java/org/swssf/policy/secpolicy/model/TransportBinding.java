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

import org.apache.neethi.*;
import org.swssf.policy.OperationPolicy;
import org.swssf.policy.assertionStates.AssertionState;
import org.swssf.policy.secpolicy.SPConstants;
import org.swssf.securityEvent.SecurityEvent;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * class lent from apache rampart
 */
public class TransportBinding extends Binding {

    private TransportToken transportToken;

    private List<TransportBinding> transportBindings;

    public TransportBinding(SPConstants spConstants) {
        super(spConstants);
    }

    /**
     * @return Returns the transportToken.
     */
    public TransportToken getTransportToken() {
        return transportToken;
    }

    /**
     * @param transportToken The transportToken to set.
     */
    public void setTransportToken(TransportToken transportToken) {
        this.transportToken = transportToken;
    }

    public List getConfigurations() {
        return transportBindings;
    }

    public TransportBinding getDefaultConfiguration() {
        if (transportBindings != null) {
            return transportBindings.get(0);
        }
        return null;
    }

    public void addConfiguration(TransportBinding transportBinding) {
        if (transportBindings == null) {
            transportBindings = new ArrayList<TransportBinding>();
        }
        transportBindings.add(transportBinding);
    }

    public QName getName() {
        return spConstants.getTransportBinding();
    }

    public PolicyComponent normalize() {
        if (isNormalized()) {
            return this;
        }

        AlgorithmSuite algorithmSuite = getAlgorithmSuite();

        Policy policy = new Policy();
        ExactlyOne exactlyOne = new ExactlyOne();
        policy.addPolicyComponent(exactlyOne);
        All all = new All();
        exactlyOne.addPolicyComponent(all);

        TransportBinding transportBinding = new TransportBinding(spConstants);
        transportBinding.setAlgorithmSuite(algorithmSuite);
        transportBinding.setIncludeTimestamp(isIncludeTimestamp());
        transportBinding.setLayout(getLayout());
        transportBinding.setSignedEndorsingSupportingTokens(getSignedEndorsingSupportingTokens());
        transportBinding.setSignedSupportingToken(getSignedSupportingToken());
        transportBinding.setTransportToken(getTransportToken());

        transportBinding.setNormalized(true);
        all.addPolicyComponent(transportBinding);

        return policy;
    }

    public void serialize(XMLStreamWriter writer) throws XMLStreamException {
        String localName = getName().getLocalPart();
        String namespaceURI = getName().getNamespaceURI();

        String prefix = writer.getPrefix(namespaceURI);

        if (prefix == null) {
            prefix = getName().getPrefix();
            writer.setPrefix(prefix, namespaceURI);
        }

        // <sp:TransportBinding>
        writer.writeStartElement(prefix, localName, namespaceURI);
        writer.writeNamespace(prefix, namespaceURI);

        String pPrefix = writer.getPrefix(SPConstants.POLICY.getNamespaceURI());
        if (pPrefix == null) {
            pPrefix = SPConstants.POLICY.getPrefix();
            writer.setPrefix(pPrefix, SPConstants.POLICY.getNamespaceURI());
        }

        // <wsp:Policy>
        writer.writeStartElement(pPrefix, SPConstants.POLICY.getLocalPart(), SPConstants.POLICY.getNamespaceURI());


        if (transportToken == null) {
            // TODO more meaningful exception
            throw new RuntimeException("no TransportToken found");
        }

        // <sp:TransportToken>
        transportToken.serialize(writer);
        // </sp:TransportToken>

        AlgorithmSuite algorithmSuite = getAlgorithmSuite();
        if (algorithmSuite == null) {
            throw new RuntimeException("no AlgorithmSuite found");
        }

        // <sp:AlgorithmSuite>
        algorithmSuite.serialize(writer);
        // </sp:AlgorithmSuite>

        Layout layout = getLayout();
        if (layout != null) {
            // <sp:Layout>
            layout.serialize(writer);
            // </sp:Layout>
        }

        if (isIncludeTimestamp()) {
            // <sp:IncludeTimestamp>
            writer.writeStartElement(prefix, SPConstants.INCLUDE_TIMESTAMP, namespaceURI);
            writer.writeEndElement();
            // </sp:IncludeTimestamp>
        }

        // </wsp:Policy>
        writer.writeEndElement();

        // </sp:TransportBinding>
        writer.writeEndElement();

    }

    @Override
    public SecurityEvent.Event[] getResponsibleAssertionEvents() {
        SecurityEvent.Event[] parentEvents = super.getResponsibleAssertionEvents();
        SecurityEvent.Event[] collectedSecurityEvents = new SecurityEvent.Event[parentEvents.length];
        System.arraycopy(parentEvents, 0, collectedSecurityEvents, 0, parentEvents.length);
        return collectedSecurityEvents;
    }

    @Override
    public void getAssertions(Map<SecurityEvent.Event, Map<Assertion, List<AssertionState>>> assertionStateMap, OperationPolicy operationPolicy) {
        super.getAssertions(assertionStateMap, operationPolicy);
        if (transportToken != null) {
            transportToken.getAssertions(assertionStateMap, operationPolicy);
        }
    }

    @Override
    public boolean isAsserted(Map<SecurityEvent.Event, Map<Assertion, List<AssertionState>>> assertionStateMap) {
        boolean isAsserted = true;
        if (transportToken != null) {
            isAsserted &= transportToken.isAsserted(assertionStateMap);
        }
        isAsserted &= super.isAsserted(assertionStateMap);
        return isAsserted;
    }
}
