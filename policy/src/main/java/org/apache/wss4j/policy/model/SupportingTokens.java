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
import org.apache.neethi.Policy;
import org.apache.neethi.PolicyComponent;
import org.apache.wss4j.policy.SPConstants;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class SupportingTokens extends AbstractTokenWrapper {

    private SupportingTokenType supportingTokenType;
    private final List<AbstractToken> tokens = new ArrayList<AbstractToken>();
    private AlgorithmSuite algorithmSuite;
    private SignedParts signedParts;
    private SignedElements signedElements;
    private EncryptedParts encryptedParts;
    private EncryptedElements encryptedElements;

    public SupportingTokens(SPConstants.SPVersion version, SupportingTokenType supportingTokenType, Policy nestedPolicy) {
        super(version, nestedPolicy);
        this.supportingTokenType = supportingTokenType;

        parseNestedPolicy(nestedPolicy, this);
    }

    @Override
    public QName getName() {
        return getSupportingTokenType().getName();
    }

    @Override
    public void serialize(XMLStreamWriter writer) throws XMLStreamException {
        super.serialize(writer, getPolicy());
    }

    @Override
    public PolicyComponent normalize() {
        return super.normalize(getPolicy());
    }

    @Override
    protected AbstractSecurityAssertion cloneAssertion(Policy nestedPolicy) {
        return new SupportingTokens(getVersion(), getSupportingTokenType(), nestedPolicy);
    }

    protected void parseNestedPolicy(Policy nestedPolicy, SupportingTokens supportingTokens) {
        Iterator<List<Assertion>> alternatives = nestedPolicy.getAlternatives();
        //we just process the first alternative
        //this means that if we have a compact policy only the first alternative is visible
        //in contrary to a normalized policy where just one alternative exists
        if (alternatives.hasNext()) {
            List<Assertion> assertions = alternatives.next();
            for (int i = 0; i < assertions.size(); i++) {
                Assertion assertion = assertions.get(i);
                String assertionName = assertion.getName().getLocalPart();
                String assertionNamespace = assertion.getName().getNamespaceURI();
                if (assertion instanceof AbstractToken) {
                    AbstractToken abstractToken = (AbstractToken) assertion;
                    supportingTokens.addToken(abstractToken);
                    abstractToken.setParentAssertion(supportingTokens);
                    continue;
                }
                if (getVersion().getSPConstants().getAlgorithmSuite().getLocalPart().equals(assertionName)
                        && getVersion().getSPConstants().getAlgorithmSuite().getNamespaceURI().equals(assertionNamespace)) {
                    if (supportingTokens.getAlgorithmSuite() != null) {
                        throw new IllegalArgumentException(SPConstants.ERR_INVALID_POLICY);
                    }
                    supportingTokens.setAlgorithmSuite((AlgorithmSuite) assertion);
                    continue;
                }
                if (getVersion().getSPConstants().getSignedParts().getLocalPart().equals(assertionName)
                        && getVersion().getSPConstants().getSignedParts().getNamespaceURI().equals(assertionNamespace)) {
                    if (supportingTokens.getSignedParts() != null) {
                        throw new IllegalArgumentException(SPConstants.ERR_INVALID_POLICY);
                    }
                    supportingTokens.setSignedParts((SignedParts) assertion);
                    continue;
                }
                if (getVersion().getSPConstants().getSignedElements().getLocalPart().equals(assertionName)
                        && getVersion().getSPConstants().getSignedElements().getNamespaceURI().equals(assertionNamespace)) {
                    if (supportingTokens.getSignedElements() != null) {
                        throw new IllegalArgumentException(SPConstants.ERR_INVALID_POLICY);
                    }
                    supportingTokens.setSignedElements((SignedElements) assertion);
                    continue;
                }
                if (getVersion().getSPConstants().getEncryptedParts().getLocalPart().equals(assertionName)
                        && getVersion().getSPConstants().getEncryptedParts().getNamespaceURI().equals(assertionNamespace)) {
                    if (supportingTokens.getEncryptedParts() != null) {
                        throw new IllegalArgumentException(SPConstants.ERR_INVALID_POLICY);
                    }
                    supportingTokens.setEncryptedParts((EncryptedParts) assertion);
                    continue;
                }
                if (getVersion().getSPConstants().getEncryptedElements().getLocalPart().equals(assertionName)
                        && getVersion().getSPConstants().getEncryptedElements().getNamespaceURI().equals(assertionNamespace)) {
                    if (supportingTokens.getEncryptedElements() != null) {
                        throw new IllegalArgumentException(SPConstants.ERR_INVALID_POLICY);
                    }
                    supportingTokens.setEncryptedElements((EncryptedElements) assertion);
                    continue;
                }
            }
        }
    }

    public SupportingTokenType getSupportingTokenType() {
        return supportingTokenType;
    }

    protected void setSupportingTokenType(SupportingTokenType supportingTokenType) {
        this.supportingTokenType = supportingTokenType;
    }

    public List<AbstractToken> getTokens() {
        return tokens;
    }

    public void addToken(AbstractToken token) {
        this.tokens.add(token);
    }

    public AlgorithmSuite getAlgorithmSuite() {
        return algorithmSuite;
    }

    protected void setAlgorithmSuite(AlgorithmSuite algorithmSuite) {
        this.algorithmSuite = algorithmSuite;
    }

    public SignedParts getSignedParts() {
        return signedParts;
    }

    protected void setSignedParts(SignedParts signedParts) {
        this.signedParts = signedParts;
    }

    public SignedElements getSignedElements() {
        return signedElements;
    }

    protected void setSignedElements(SignedElements signedElements) {
        this.signedElements = signedElements;
    }

    public EncryptedParts getEncryptedParts() {
        return encryptedParts;
    }

    protected void setEncryptedParts(EncryptedParts encryptedParts) {
        this.encryptedParts = encryptedParts;
    }

    public EncryptedElements getEncryptedElements() {
        return encryptedElements;
    }

    protected void setEncryptedElements(EncryptedElements encryptedElements) {
        this.encryptedElements = encryptedElements;
    }
    
    /**
     * @return true if the supporting token should be encrypted
     */
    public boolean isEncryptedToken() {
        QName name = getName();
        if (name != null && name.getLocalPart().contains("Encrypted")) {
            return true;
        }
        return false;
    }
    
    /**
     * @return true if the supporting token is endorsing
     */
    public boolean isEndorsing() {
        QName name = getName();
        if (name != null && name.getLocalPart().contains("Endorsing")) {
            return true;
        }
        return false;
    }
}
