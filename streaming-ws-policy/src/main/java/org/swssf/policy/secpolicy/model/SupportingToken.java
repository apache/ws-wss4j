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
import org.swssf.policy.assertionStates.EncryptedElementAssertionState;
import org.swssf.policy.assertionStates.SignedElementAssertionState;
import org.swssf.policy.secpolicy.PolicyUtil;
import org.swssf.policy.secpolicy.SP12Constants;
import org.swssf.policy.secpolicy.SPConstants;
import org.swssf.wss.securityEvent.SecurityEvent;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * class lent from apache rampart
 */
public class SupportingToken extends AbstractSecurityAssertion implements
        AlgorithmWrapper, TokenWrapper {

    /**
     * Type of SupportingToken
     *
     * @see SPConstants.SupportingTokenType#SUPPORTING
     * @see SPConstants.SupportingTokenType#ENDORSING
     * @see SPConstants.SupportingTokenType#SIGNED
     * @see SPConstants.SupportingTokenType#SIGNED_ENDORSING
     */
    private SPConstants.SupportingTokenType type;

    private AlgorithmSuite algorithmSuite;

    private Token token;

    private SignedEncryptedElements signedElements;

    private SignedEncryptedElements encryptedElements;

    private SignedEncryptedParts signedParts;

    private SignedEncryptedParts encryptedParts;

    public SupportingToken(SPConstants.SupportingTokenType type, SPConstants spConstants) {
        this.type = type;
        setVersion(spConstants);
    }

    /**
     * @return Returns the algorithmSuite.
     */
    public AlgorithmSuite getAlgorithmSuite() {
        return algorithmSuite;
    }

    /**
     * @param algorithmSuite The algorithmSuite to set.
     */
    public void setAlgorithmSuite(AlgorithmSuite algorithmSuite) {
        this.algorithmSuite = algorithmSuite;
    }

    /**
     * @return Returns the token.
     */
    public Token getTokens() {
        return token;
    }

    /**
     * @param token The token to set.
     */
    public void setToken(Token token) {
        this.token = token;
    }

    /**
     * @return Returns the type.
     */
    public SPConstants.SupportingTokenType getTokenType() {
        return type;
    }

    /**
     * @param type The type to set.
     */
    public void setTokenType(SPConstants.SupportingTokenType type) {
        this.type = type;
    }

    /**
     * @return Returns the encryptedElements.
     */
    public SignedEncryptedElements getEncryptedElements() {
        return encryptedElements;
    }

    /**
     * @param encryptedElements The encryptedElements to set.
     */
    public void setEncryptedElements(SignedEncryptedElements encryptedElements) {
        this.encryptedElements = encryptedElements;
    }

    /**
     * @return Returns the encryptedParts.
     */
    public SignedEncryptedParts getEncryptedParts() {
        return encryptedParts;
    }

    /**
     * @param encryptedParts The encryptedParts to set.
     */
    public void setEncryptedParts(SignedEncryptedParts encryptedParts) {
        this.encryptedParts = encryptedParts;
    }

    /**
     * @return Returns the signedElements.
     */
    public SignedEncryptedElements getSignedElements() {
        return signedElements;
    }

    /**
     * @param signedElements The signedElements to set.
     */
    public void setSignedElements(SignedEncryptedElements signedElements) {
        this.signedElements = signedElements;
    }

    /**
     * @return Returns the signedParts.
     */
    public SignedEncryptedParts getSignedParts() {
        return signedParts;
    }

    /**
     * @param signedParts The signedParts to set.
     */
    public void setSignedParts(SignedEncryptedParts signedParts) {
        this.signedParts = signedParts;
    }

    public QName getName() {
        switch (type) {
            case SUPPORTING:
                return spConstants.getSupportingTokens();
            case ENDORSING:
                return spConstants.getEndorsingSupportingTokens();
            case SIGNED:
                return spConstants.getSignedSupportingTokens();
            case SIGNED_ENDORSING:
                return spConstants.getSignedEndorsingSupportingTokens();
            case SIGNED_ENCRYPTED:
                return SP12Constants.SIGNED_ENCRYPTED_SUPPORTING_TOKENS;
            case ENCRYPTED:
                return SP12Constants.ENCRYPTED_SUPPORTING_TOKENS;
            case ENDORSING_ENCRYPTED:
                return SP12Constants.ENDORSING_ENCRYPTED_SUPPORTING_TOKENS;
            case SIGNED_ENDORSING_ENCRYPTED:
                return SP12Constants.SIGNED_ENDORSING_ENCRYPTED_SUPPORTING_TOKENS;
            default:
                return null;
        }
    }

    /**
     * @return true if the supporting token should be encrypted
     */

    public boolean isEncryptedToken() {
        switch (type) {
            case SUPPORTING:
                return false;
            case ENDORSING:
                return false;
            case SIGNED:
                return false;
            case SIGNED_ENDORSING:
                return false;
            case SIGNED_ENCRYPTED:
                return true;
            case ENCRYPTED:
                return true;
            case ENDORSING_ENCRYPTED:
                return true;
            case SIGNED_ENDORSING_ENCRYPTED:
                return true;
            default:
                return false;
        }
    }

    public PolicyComponent normalize() {
        return this;
    }

    public short getType() {
        return org.apache.neethi.Constants.TYPE_ASSERTION;
    }

    public void serialize(XMLStreamWriter writer) throws XMLStreamException {
        String namespaceURI = getName().getNamespaceURI();

        String prefix = writer.getPrefix(namespaceURI);
        if (prefix == null) {
            prefix = getName().getPrefix();
            writer.setPrefix(prefix, namespaceURI);
        }

        String localname = getName().getLocalPart();

        // <sp:SupportingToken>
        writer.writeStartElement(prefix, localname, namespaceURI);

        // xmlns:sp=".."
        writer.writeNamespace(prefix, namespaceURI);

        String pPrefix = writer.getPrefix(SPConstants.POLICY.getNamespaceURI());
        if (pPrefix == null) {
            pPrefix = SPConstants.POLICY.getPrefix();
            writer.setPrefix(pPrefix, SPConstants.POLICY.getNamespaceURI());
        }
        // <wsp:Policy>
        writer.writeStartElement(pPrefix, SPConstants.POLICY.getLocalPart(),
                SPConstants.POLICY.getNamespaceURI());

        // [Token Assertion] +
        token.serialize(writer);


        if (signedParts != null) {
            signedParts.serialize(writer);

        } else if (signedElements != null) {
            signedElements.serialize(writer);

        } else if (encryptedParts != null) {
            encryptedParts.serialize(writer);

        } else if (encryptedElements != null) {
            encryptedElements.serialize(writer);
        }
        // </wsp:Policy>
        writer.writeEndElement();

        writer.writeEndElement();
        // </sp:SupportingToken>
    }

    @Override
    public SecurityEvent.Event[] getResponsibleAssertionEvents() {
        return new SecurityEvent.Event[]{SecurityEvent.Event.SupportingToken};
    }

    @Override
    public void getAssertions(Map<SecurityEvent.Event, Map<Assertion, List<AssertionState>>> assertionStateMap, OperationPolicy operationPolicy) {
        token.getAssertions(assertionStateMap, operationPolicy);
        boolean signed = false;
        boolean encrypted = false;
        switch (type) {
            case SUPPORTING:
                break;
            case ENDORSING:
                break;
            case SIGNED:
                signed = true;
                break;
            case SIGNED_ENDORSING:
                signed = true;
                break;
            case SIGNED_ENCRYPTED:
                signed = true;
                encrypted = true;
                break;
            case ENCRYPTED:
                encrypted = true;
                break;
            case ENDORSING_ENCRYPTED:
                encrypted = true;
                break;
            case SIGNED_ENDORSING_ENCRYPTED:
                signed = true;
                encrypted = true;
                break;
        }
        if (signed) {
            QName xmlName = token.getXmlName();
            Map<Assertion, List<AssertionState>> signedElementAssertionStates = assertionStateMap.get(SecurityEvent.Event.SignedElement);
            List<QName> qNames = new ArrayList<QName>();
            qNames.add(xmlName);

            SignedEncryptedElements signedEncryptedElements = null;
            List<Assertion> assertions = PolicyUtil.getPolicyAssertionsInSameAlternative(operationPolicy.getPolicy(), this, SignedEncryptedElements.class, Boolean.TRUE, spConstants);
            for (int i = 0; i < assertions.size(); i++) {
                signedEncryptedElements = (SignedEncryptedElements) assertions.get(i);
                if (signedEncryptedElements.isSignedElements()) {
                    break;
                }
            }
            addAssertionState(signedElementAssertionStates, signedEncryptedElements, new SignedElementAssertionState(signedEncryptedElements, true, qNames));
        }
        if (encrypted) {
            QName xmlName = token.getXmlName();
            Map<Assertion, List<AssertionState>> encryptedElementAssertionStates = assertionStateMap.get(SecurityEvent.Event.EncryptedElement);
            List<QName> qNames = new ArrayList<QName>();
            qNames.add(xmlName);

            SignedEncryptedElements signedEncryptedElements = null;
            List<Assertion> assertions = PolicyUtil.getPolicyAssertionsInSameAlternative(operationPolicy.getPolicy(), this, SignedEncryptedElements.class, Boolean.TRUE, spConstants);
            for (int i = 0; i < assertions.size(); i++) {
                signedEncryptedElements = (SignedEncryptedElements) assertions.get(i);
                if (signedEncryptedElements.isSignedElements()) {
                    break;
                }
            }
            addAssertionState(encryptedElementAssertionStates, signedEncryptedElements, new EncryptedElementAssertionState(signedEncryptedElements, true, qNames));
        }
    }
}
