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
package org.apache.ws.security.policy.model;

import org.apache.neethi.Assertion;
import org.apache.neethi.Policy;
import org.apache.ws.security.policy.SPConstants;

import javax.xml.namespace.QName;
import java.util.Iterator;
import java.util.List;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class SymmetricBinding extends AbstractSymmetricAsymmetricBinding {

    private EncryptionToken encryptionToken;
    private SignatureToken signatureToken;
    private ProtectionToken protectionToken;

    public SymmetricBinding(SPConstants.SPVersion version, Policy nestedPolicy) {
        super(version, nestedPolicy);

        parseNestedPolicy(nestedPolicy, this);
    }

    public QName getName() {
        return getVersion().getSPConstants().getSymmetricBinding();
    }

    @Override
    protected AbstractSecurityAssertion cloneAssertion(Policy nestedPolicy) {
        return new SymmetricBinding(getVersion(), nestedPolicy);
    }

    protected void parseNestedPolicy(Policy nestedPolicy, SymmetricBinding symmetricBinding) {
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
                if (getVersion().getSPConstants().getEncryptionToken().getLocalPart().equals(assertionName)
                        && getVersion().getSPConstants().getEncryptionToken().getNamespaceURI().equals(assertionNamespace)) {
                    if (symmetricBinding.getEncryptionToken() != null || symmetricBinding.getProtectionToken() != null) {
                        throw new IllegalArgumentException(SPConstants.ERR_INVALID_POLICY);
                    }
                    symmetricBinding.setEncryptionToken((EncryptionToken) assertion);
                    continue;
                }
                if (getVersion().getSPConstants().getSignatureToken().getLocalPart().equals(assertionName)
                        && getVersion().getSPConstants().getSignatureToken().getNamespaceURI().equals(assertionNamespace)) {
                    if (symmetricBinding.getSignatureToken() != null || symmetricBinding.getProtectionToken() != null) {
                        throw new IllegalArgumentException(SPConstants.ERR_INVALID_POLICY);
                    }
                    symmetricBinding.setSignatureToken((SignatureToken) assertion);
                    continue;
                }
                if (getVersion().getSPConstants().getProtectionToken().getLocalPart().equals(assertionName)
                        && getVersion().getSPConstants().getProtectionToken().getNamespaceURI().equals(assertionNamespace)) {
                    if (symmetricBinding.getProtectionToken() != null
                            || symmetricBinding.getEncryptionToken() != null
                            || symmetricBinding.getSignatureToken() != null) {
                        throw new IllegalArgumentException(SPConstants.ERR_INVALID_POLICY);
                    }
                    symmetricBinding.setProtectionToken((ProtectionToken) assertion);
                    continue;
                }
            }
        }
    }

    public EncryptionToken getEncryptionToken() {
        return encryptionToken;
    }

    protected void setEncryptionToken(EncryptionToken encryptionToken) {
        this.encryptionToken = encryptionToken;
    }

    public SignatureToken getSignatureToken() {
        return signatureToken;
    }

    protected void setSignatureToken(SignatureToken signatureToken) {
        this.signatureToken = signatureToken;
    }

    public ProtectionToken getProtectionToken() {
        return protectionToken;
    }

    protected void setProtectionToken(ProtectionToken protectionToken) {
        this.protectionToken = protectionToken;
    }
}
