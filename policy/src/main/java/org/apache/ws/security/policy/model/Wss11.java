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
public class Wss11 extends Wss10 {

    private boolean mustSupportRefThumbprint;
    private boolean mustSupportRefEncryptedKey;
    private boolean requireSignatureConfirmation;

    public Wss11(SPConstants.SPVersion version, Policy nestedPolicy) {
        super(version, nestedPolicy);

        parseNestedWss11Policy(nestedPolicy, this);
    }

    @Override
    public QName getName() {
        return getVersion().getSPConstants().getWss11();
    }

    @Override
    protected AbstractSecurityAssertion cloneAssertion(Policy nestedPolicy) {
        return new Wss11(getVersion(), nestedPolicy);
    }

    protected void parseNestedWss11Policy(Policy nestedPolicy, Wss11 wss11) {
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
                if (getVersion().getSPConstants().getMustSupportRefThumbprint().getLocalPart().equals(assertionName)
                        && getVersion().getSPConstants().getMustSupportRefThumbprint().getNamespaceURI().equals(assertionNamespace)) {
                    if (wss11.isMustSupportRefThumbprint()) {
                        throw new IllegalArgumentException(SPConstants.ERR_INVALID_POLICY);
                    }
                    wss11.setMustSupportRefThumbprint(true);
                    continue;
                }
                if (getVersion().getSPConstants().getMustSupportRefEncryptedKey().getLocalPart().equals(assertionName)
                        && getVersion().getSPConstants().getMustSupportRefEncryptedKey().getNamespaceURI().equals(assertionNamespace)) {
                    if (wss11.isMustSupportRefEncryptedKey()) {
                        throw new IllegalArgumentException(SPConstants.ERR_INVALID_POLICY);
                    }
                    wss11.setMustSupportRefEncryptedKey(true);
                    continue;
                }
                if (getVersion().getSPConstants().getRequireSignatureConfirmation().getLocalPart().equals(assertionName)
                        && getVersion().getSPConstants().getRequireSignatureConfirmation().getNamespaceURI().equals(assertionNamespace)) {
                    if (wss11.isRequireSignatureConfirmation()) {
                        throw new IllegalArgumentException(SPConstants.ERR_INVALID_POLICY);
                    }
                    wss11.setRequireSignatureConfirmation(true);
                    continue;
                }
            }
        }
    }

    public boolean isMustSupportRefThumbprint() {
        return mustSupportRefThumbprint;
    }

    protected void setMustSupportRefThumbprint(boolean mustSupportRefThumbprint) {
        this.mustSupportRefThumbprint = mustSupportRefThumbprint;
    }

    public boolean isMustSupportRefEncryptedKey() {
        return mustSupportRefEncryptedKey;
    }

    protected void setMustSupportRefEncryptedKey(boolean mustSupportRefEncryptedKey) {
        this.mustSupportRefEncryptedKey = mustSupportRefEncryptedKey;
    }

    public boolean isRequireSignatureConfirmation() {
        return requireSignatureConfirmation;
    }

    protected void setRequireSignatureConfirmation(boolean requireSignatureConfirmation) {
        this.requireSignatureConfirmation = requireSignatureConfirmation;
    }
}
