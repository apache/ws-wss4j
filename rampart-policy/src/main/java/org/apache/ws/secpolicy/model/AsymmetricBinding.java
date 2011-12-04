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
package org.apache.ws.secpolicy.model;

import org.apache.neethi.Assertion;
import org.apache.neethi.Policy;
import org.apache.ws.secpolicy.SPConstants;

import javax.xml.namespace.QName;
import java.util.Iterator;
import java.util.List;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
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

    public QName getName() {
        return getVersion().getSPConstants().getAsymmetricBinding();
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
                if (getVersion().getSPConstants().getInitiatorToken().getLocalPart().equals(assertionName)
                        && getVersion().getSPConstants().getInitiatorToken().getNamespaceURI().equals(assertionNamespace)) {
                    if (asymmetricBinding.getInitiatorToken() != null
                            || asymmetricBinding.getInitiatorSignatureToken() != null
                            || asymmetricBinding.getInitiatorEncryptionToken() != null) {
                        throw new IllegalArgumentException(SPConstants.ERR_INVALID_POLICY);
                    }
                    asymmetricBinding.setInitiatorToken((InitiatorToken) assertion);
                    continue;
                }
                if (getVersion().getSPConstants().getInitiatorSignatureToken().getLocalPart().equals(assertionName)
                        && getVersion().getSPConstants().getInitiatorSignatureToken().getNamespaceURI().equals(assertionNamespace)) {
                    if (asymmetricBinding.getInitiatorToken() != null
                            || asymmetricBinding.getInitiatorSignatureToken() != null) {
                        throw new IllegalArgumentException(SPConstants.ERR_INVALID_POLICY);
                    }
                    asymmetricBinding.setInitiatorSignatureToken((InitiatorSignatureToken) assertion);
                    continue;
                }
                if (getVersion().getSPConstants().getInitiatorEncryptionToken().getLocalPart().equals(assertionName)
                        && getVersion().getSPConstants().getInitiatorEncryptionToken().getNamespaceURI().equals(assertionNamespace)) {
                    if (asymmetricBinding.getInitiatorToken() != null
                            || asymmetricBinding.getInitiatorEncryptionToken() != null) {
                        throw new IllegalArgumentException(SPConstants.ERR_INVALID_POLICY);
                    }
                    asymmetricBinding.setInitiatorEncryptionToken((InitiatorEncryptionToken) assertion);
                    continue;
                }
                if (getVersion().getSPConstants().getRecipientToken().getLocalPart().equals(assertionName)
                        && getVersion().getSPConstants().getRecipientToken().getNamespaceURI().equals(assertionNamespace)) {
                    if (asymmetricBinding.getRecipientToken() != null
                            || asymmetricBinding.getRecipientSignatureToken() != null
                            || asymmetricBinding.getRecipientEncryptionToken() != null) {
                        throw new IllegalArgumentException(SPConstants.ERR_INVALID_POLICY);
                    }
                    asymmetricBinding.setRecipientToken((RecipientToken) assertion);
                    continue;
                }
                if (getVersion().getSPConstants().getRecipientSignatureToken().getLocalPart().equals(assertionName)
                        && getVersion().getSPConstants().getRecipientSignatureToken().getNamespaceURI().equals(assertionNamespace)) {
                    if (asymmetricBinding.getRecipientToken() != null
                            || asymmetricBinding.getRecipientSignatureToken() != null) {
                        throw new IllegalArgumentException(SPConstants.ERR_INVALID_POLICY);
                    }
                    asymmetricBinding.setRecipientSignatureToken((RecipientSignatureToken) assertion);
                    continue;
                }
                if (getVersion().getSPConstants().getRecipientEncryptionToken().getLocalPart().equals(assertionName)
                        && getVersion().getSPConstants().getRecipientEncryptionToken().getNamespaceURI().equals(assertionNamespace)) {
                    if (asymmetricBinding.getRecipientToken() != null
                            || asymmetricBinding.getRecipientEncryptionToken() != null) {
                        throw new IllegalArgumentException(SPConstants.ERR_INVALID_POLICY);
                    }
                    asymmetricBinding.setRecipientEncryptionToken((RecipientEncryptionToken) assertion);
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
