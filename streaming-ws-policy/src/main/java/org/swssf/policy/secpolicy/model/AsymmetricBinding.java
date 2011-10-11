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
import org.swssf.wss.securityEvent.SecurityEvent;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;
import java.util.List;
import java.util.Map;

/**
 * class lent from apache rampart
 */
public class AsymmetricBinding extends SymmetricAsymmetricBindingBase {

    private InitiatorToken initiatorToken;

    private RecipientToken recipientToken;

    public AsymmetricBinding(SPConstants spConstants) {
        super(spConstants);
    }

    /**
     * @return Returns the initiatorToken.
     */
    public InitiatorToken getInitiatorToken() {
        return initiatorToken;
    }

    /**
     * @param initiatorToken The initiatorToken to set.
     */
    public void setInitiatorToken(InitiatorToken initiatorToken) {
        this.initiatorToken = initiatorToken;
    }

    /**
     * @return Returns the recipientToken.
     */
    public RecipientToken getRecipientToken() {
        return recipientToken;
    }

    /**
     * @param recipientToken The recipientToken to set.
     */
    public void setRecipientToken(RecipientToken recipientToken) {
        this.recipientToken = recipientToken;
    }

    public QName getName() {
        return spConstants.getAsymmetricBinding();
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

        AsymmetricBinding asymmetricBinding = new AsymmetricBinding(spConstants);

        asymmetricBinding.setAlgorithmSuite(algorithmSuite);
        asymmetricBinding.setEntireHeadersAndBodySignatures(isEntireHeadersAndBodySignatures());
        asymmetricBinding.setIncludeTimestamp(isIncludeTimestamp());
        asymmetricBinding.setInitiatorToken(getInitiatorToken());
        asymmetricBinding.setLayout(getLayout());
        asymmetricBinding.setProtectionOrder(getProtectionOrder());
        asymmetricBinding.setRecipientToken(getRecipientToken());
        asymmetricBinding.setSignatureProtection(isSignatureProtection());
        asymmetricBinding.setSignedEndorsingSupportingTokens(getSignedEndorsingSupportingTokens());
        asymmetricBinding.setSignedSupportingToken(getSignedSupportingToken());
        asymmetricBinding.setTokenProtection(isTokenProtection());

        asymmetricBinding.setNormalized(true);
        all.addPolicyComponent(asymmetricBinding);

        return policy;

    }

    public void serialize(XMLStreamWriter writer) throws XMLStreamException {
        String localname = getName().getLocalPart();
        String namespaceURI = getName().getNamespaceURI();

        String prefix = writer.getPrefix(namespaceURI);

        if (prefix == null) {
            prefix = getName().getPrefix();
            writer.setPrefix(prefix, namespaceURI);
        }

        // <sp:AsymmetricBinding>
        writer.writeStartElement(prefix, localname, namespaceURI);
        writer.writeNamespace(prefix, namespaceURI);

        String pPrefix = writer.getPrefix(SPConstants.POLICY.getNamespaceURI());
        if (pPrefix == null) {
            pPrefix = SPConstants.POLICY.getPrefix();
            writer.setPrefix(pPrefix, SPConstants.POLICY.getNamespaceURI());
        }

        // <wsp:Policy>
        writer.writeStartElement(pPrefix, SPConstants.POLICY.getLocalPart(),
                SPConstants.POLICY.getNamespaceURI());

        if (initiatorToken == null) {
            throw new RuntimeException("InitiatorToken is not set");
        }

        // <sp:InitiatorToken>
        initiatorToken.serialize(writer);
        // </sp:InitiatorToken>

        if (recipientToken == null) {
            throw new RuntimeException("RecipientToken is not set");
        }

        // <sp:RecipientToken>
        recipientToken.serialize(writer);
        // </sp:RecipientToken>

        AlgorithmSuite algorithmSuite = getAlgorithmSuite();
        if (algorithmSuite == null) {
            throw new RuntimeException("AlgorithmSuite is not set");
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
            writer.writeStartElement(prefix, SPConstants.INCLUDE_TIMESTAMP,
                    namespaceURI);
            writer.writeEndElement();
            // </sp:IncludeTimestamp>
        }

        if (SPConstants.ProtectionOrder.EncryptBeforeSigning.equals(getProtectionOrder())) {
            // <sp:EncryptBeforeSign />
            writer.writeStartElement(prefix, SPConstants.ENCRYPT_BEFORE_SIGNING,
                    namespaceURI);
            writer.writeEndElement();
        }

        if (isSignatureProtection()) {
            // <sp:EncryptSignature />
            // FIXME move the String constants to a QName
            writer.writeStartElement(prefix, SPConstants.ENCRYPT_SIGNATURE,
                    namespaceURI);
            writer.writeEndElement();
        }

        if (isTokenProtection()) {
            // <sp:ProtectTokens />
            writer.writeStartElement(prefix, SPConstants.PROTECT_TOKENS,
                    namespaceURI);
            writer.writeEndElement();
        }

        if (isEntireHeadersAndBodySignatures()) {
            // <sp:OnlySignEntireHeaderAndBody />
            writer.writeStartElement(prefix,
                    SPConstants.ONLY_SIGN_ENTIRE_HEADERS_AND_BODY, namespaceURI);
            writer.writeEndElement();
        }

        // </wsp:Policy>
        writer.writeEndElement();

        // </sp:AsymmetircBinding>
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
        if (initiatorToken != null) {
            initiatorToken.getAssertions(assertionStateMap, operationPolicy);
        }
        if (recipientToken != null) {
            recipientToken.getAssertions(assertionStateMap, operationPolicy);
        }
    }

    @Override
    public boolean isAsserted(Map<SecurityEvent.Event, Map<Assertion, List<AssertionState>>> assertionStateMap) {
        boolean isAsserted = true;
        if (initiatorToken != null) {
            isAsserted &= initiatorToken.isAsserted(assertionStateMap);
        }
        if (recipientToken != null) {
            isAsserted &= recipientToken.isAsserted(assertionStateMap);
        }
        isAsserted &= super.isAsserted(assertionStateMap);
        return isAsserted;
    }
}
