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
import org.apache.wss4j.policy.SPConstants;

import javax.xml.namespace.QName;
import java.util.Iterator;
import java.util.List;

public class AsymmetricBinding extends AbstractSymmetricAsymmetricBinding {

    private InitiatorToken initiatorToken;
    private InitiatorSignatureToken initiatorSignatureToken;
    private InitiatorEncryptionToken initiatorEncryptionToken;
    private RecipientToken recipientToken;
    private RecipientSignatureToken recipientSignatureToken;
    private RecipientEncryptionToken recipientEncryptionToken;

    public AsymmetricBinding(SPConstants.SPVersion version, Policy nestedPolicy) {
        super(version, nestedPolicy);

        parseNestedPolicy(nestedPolicy, this);
    }

    @Override
    public QName getName() {
        return getVersion().getSPConstants().getAsymmetricBinding();
    }

    @Override
    public boolean equals(Object object) {
        if (object == this) {
            return true;
        }

        if (!(object instanceof AsymmetricBinding)) {
            return false;
        }

        AsymmetricBinding that = (AsymmetricBinding)object;
        if (initiatorToken != null && !initiatorToken.equals(that.initiatorToken)
            || initiatorToken == null && that.initiatorToken != null) {
            return false;
        }
        if (initiatorSignatureToken != null && !initiatorSignatureToken.equals(that.initiatorSignatureToken)
            || initiatorSignatureToken == null && that.initiatorSignatureToken != null) {
            return false;
        }
        if (initiatorEncryptionToken != null && !initiatorEncryptionToken.equals(that.initiatorEncryptionToken)
            || initiatorEncryptionToken == null && that.initiatorEncryptionToken != null) {
            return false;
        }

        if (recipientToken != null && !recipientToken.equals(that.recipientToken)
            || recipientToken == null && that.recipientToken != null) {
            return false;
        }
        if (recipientSignatureToken != null && !recipientSignatureToken.equals(that.recipientSignatureToken)
            || recipientSignatureToken == null && that.recipientSignatureToken != null) {
            return false;
        }
        if (recipientEncryptionToken != null && !recipientEncryptionToken.equals(that.recipientEncryptionToken)
            || recipientEncryptionToken == null && that.recipientEncryptionToken != null) {
            return false;
        }

        return super.equals(object);
    }

    @Override
    public int hashCode() {
        int result = 17;
        if (initiatorToken != null) {
            result = 31 * result + initiatorToken.hashCode();
        }
        if (initiatorSignatureToken != null) {
            result = 31 * result + initiatorSignatureToken.hashCode();
        }
        if (initiatorEncryptionToken != null) {
            result = 31 * result + initiatorEncryptionToken.hashCode();
        }

        if (recipientToken != null) {
            result = 31 * result + recipientToken.hashCode();
        }
        if (recipientSignatureToken != null) {
            result = 31 * result + recipientSignatureToken.hashCode();
        }
        if (recipientEncryptionToken != null) {
            result = 31 * result + recipientEncryptionToken.hashCode();
        }

        return 31 * result + super.hashCode();
    }

    @Override
    protected AbstractSecurityAssertion cloneAssertion(Policy nestedPolicy) {
        return new AsymmetricBinding(getVersion(), nestedPolicy);
    }

    protected void parseNestedPolicy(Policy nestedPolicy, AsymmetricBinding asymmetricBinding) {
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

                QName initiatorToken = getVersion().getSPConstants().getInitiatorToken();
                if (initiatorToken.getLocalPart().equals(assertionName)
                    && initiatorToken.getNamespaceURI().equals(assertionNamespace)) {
                    if (asymmetricBinding.getInitiatorToken() != null
                            || asymmetricBinding.getInitiatorSignatureToken() != null
                            || asymmetricBinding.getInitiatorEncryptionToken() != null) {
                        throw new IllegalArgumentException(SPConstants.ERR_INVALID_POLICY);
                    }
                    final InitiatorToken initiatorToken1 = (InitiatorToken) assertion;
                    asymmetricBinding.setInitiatorToken(initiatorToken1);
                    initiatorToken1.setParentAssertion(asymmetricBinding);
                    continue;
                }

                QName initiatorSigToken = getVersion().getSPConstants().getInitiatorSignatureToken();
                if (initiatorSigToken.getLocalPart().equals(assertionName)
                    && initiatorSigToken.getNamespaceURI().equals(assertionNamespace)) {
                    if (asymmetricBinding.getInitiatorToken() != null
                            || asymmetricBinding.getInitiatorSignatureToken() != null) {
                        throw new IllegalArgumentException(SPConstants.ERR_INVALID_POLICY);
                    }
                    final InitiatorSignatureToken initiatorSignatureToken1 = (InitiatorSignatureToken) assertion;
                    asymmetricBinding.setInitiatorSignatureToken(initiatorSignatureToken1);
                    initiatorSignatureToken1.setParentAssertion(asymmetricBinding);
                    continue;
                }

                QName initiatorEncToken = getVersion().getSPConstants().getInitiatorEncryptionToken();
                if (initiatorEncToken.getLocalPart().equals(assertionName)
                    && initiatorEncToken.getNamespaceURI().equals(assertionNamespace)) {
                    if (asymmetricBinding.getInitiatorToken() != null
                            || asymmetricBinding.getInitiatorEncryptionToken() != null) {
                        throw new IllegalArgumentException(SPConstants.ERR_INVALID_POLICY);
                    }
                    final InitiatorEncryptionToken initiatorEncryptionToken1 = (InitiatorEncryptionToken) assertion;
                    asymmetricBinding.setInitiatorEncryptionToken(initiatorEncryptionToken1);
                    initiatorEncryptionToken1.setParentAssertion(asymmetricBinding);
                    continue;
                }

                QName recipientToken = getVersion().getSPConstants().getRecipientToken();
                if (recipientToken.getLocalPart().equals(assertionName)
                    && recipientToken.getNamespaceURI().equals(assertionNamespace)) {
                    if (asymmetricBinding.getRecipientToken() != null
                            || asymmetricBinding.getRecipientSignatureToken() != null
                            || asymmetricBinding.getRecipientEncryptionToken() != null) {
                        throw new IllegalArgumentException(SPConstants.ERR_INVALID_POLICY);
                    }
                    final RecipientToken recipientToken1 = (RecipientToken) assertion;
                    asymmetricBinding.setRecipientToken(recipientToken1);
                    recipientToken1.setParentAssertion(asymmetricBinding);
                    continue;
                }

                QName recipientSigToken = getVersion().getSPConstants().getRecipientSignatureToken();
                if (recipientSigToken.getLocalPart().equals(assertionName)
                    && recipientSigToken.getNamespaceURI().equals(assertionNamespace)) {
                    if (asymmetricBinding.getRecipientToken() != null
                            || asymmetricBinding.getRecipientSignatureToken() != null) {
                        throw new IllegalArgumentException(SPConstants.ERR_INVALID_POLICY);
                    }
                    final RecipientSignatureToken recipientSignatureToken1 = (RecipientSignatureToken) assertion;
                    asymmetricBinding.setRecipientSignatureToken(recipientSignatureToken1);
                    recipientSignatureToken1.setParentAssertion(asymmetricBinding);
                    continue;
                }

                QName recipientEncToken = getVersion().getSPConstants().getRecipientEncryptionToken();
                if (recipientEncToken.getLocalPart().equals(assertionName)
                    && recipientEncToken.getNamespaceURI().equals(assertionNamespace)) {
                    if (asymmetricBinding.getRecipientToken() != null
                            || asymmetricBinding.getRecipientEncryptionToken() != null) {
                        throw new IllegalArgumentException(SPConstants.ERR_INVALID_POLICY);
                    }
                    final RecipientEncryptionToken recipientEncryptionToken1 = (RecipientEncryptionToken) assertion;
                    asymmetricBinding.setRecipientEncryptionToken(recipientEncryptionToken1);
                    recipientEncryptionToken1.setParentAssertion(asymmetricBinding);
                    continue;
                }
            }
        }
    }

    public InitiatorToken getInitiatorToken() {
        return initiatorToken;
    }

    protected void setInitiatorToken(InitiatorToken initiatorToken) {
        this.initiatorToken = initiatorToken;
    }

    public InitiatorSignatureToken getInitiatorSignatureToken() {
        return initiatorSignatureToken;
    }

    protected void setInitiatorSignatureToken(InitiatorSignatureToken initiatorSignatureToken) {
        this.initiatorSignatureToken = initiatorSignatureToken;
    }

    public InitiatorEncryptionToken getInitiatorEncryptionToken() {
        return initiatorEncryptionToken;
    }

    protected void setInitiatorEncryptionToken(InitiatorEncryptionToken initiatorEncryptionToken) {
        this.initiatorEncryptionToken = initiatorEncryptionToken;
    }

    public RecipientToken getRecipientToken() {
        return recipientToken;
    }

    protected void setRecipientToken(RecipientToken recipientToken) {
        this.recipientToken = recipientToken;
    }

    public RecipientSignatureToken getRecipientSignatureToken() {
        return recipientSignatureToken;
    }

    protected void setRecipientSignatureToken(RecipientSignatureToken recipientSignatureToken) {
        this.recipientSignatureToken = recipientSignatureToken;
    }

    public RecipientEncryptionToken getRecipientEncryptionToken() {
        return recipientEncryptionToken;
    }

    protected void setRecipientEncryptionToken(RecipientEncryptionToken recipientEncryptionToken) {
        this.recipientEncryptionToken = recipientEncryptionToken;
    }
}
