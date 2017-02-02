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

import java.util.*;

import javax.xml.namespace.QName;

public abstract class AbstractSymmetricAsymmetricBinding extends AbstractBinding {

    public enum ProtectionOrder {
        EncryptBeforeSigning,
        SignBeforeEncrypting;

        private static final Map<String, ProtectionOrder> LOOKUP = new HashMap<>();

        static {
            for (ProtectionOrder u : EnumSet.allOf(ProtectionOrder.class)) {
                LOOKUP.put(u.name(), u);
            }
        }

        public static ProtectionOrder lookUp(String name) {
            return LOOKUP.get(name);
        }
    }

    private ProtectionOrder protectionOrder = ProtectionOrder.SignBeforeEncrypting;
    private boolean encryptSignature = false;
    private boolean protectTokens = false;
    private boolean onlySignEntireHeadersAndBody = false;

    protected AbstractSymmetricAsymmetricBinding(SPConstants.SPVersion version, Policy nestedPolicy) {
        super(version, nestedPolicy);

        parseNestedSymmetricAsymmetricBindingBasePolicy(nestedPolicy, this);
    }
    
    @Override
    public boolean equals(Object object) {
        if (object == this) {
            return true;
        }
        
        if (!(object instanceof AbstractSymmetricAsymmetricBinding)) {
            return false;
        }
        
        AbstractSymmetricAsymmetricBinding that = (AbstractSymmetricAsymmetricBinding)object;
        if (protectionOrder != that.protectionOrder
            || encryptSignature != that.encryptSignature
            || protectTokens != that.protectTokens
            || onlySignEntireHeadersAndBody != that.onlySignEntireHeadersAndBody) {
            return false;
        }
        
        return super.equals(object);
    }
    
    @Override
    public int hashCode() {
        int result = 17;
        if (protectionOrder != null) {
            result = 31 * result + protectionOrder.hashCode();
        }
        result = 31 * result + Boolean.hashCode(encryptSignature);
        result = 31 * result + Boolean.hashCode(protectTokens);
        result = 31 * result + Boolean.hashCode(onlySignEntireHeadersAndBody);
        
        return 31 * result + super.hashCode();
    }

    protected void parseNestedSymmetricAsymmetricBindingBasePolicy(
        Policy nestedPolicy,  AbstractSymmetricAsymmetricBinding asymmetricBindingBase
    ) {
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
                ProtectionOrder protectionOrder = ProtectionOrder.lookUp(assertionName);
                if (protectionOrder != null) {
                    if (asymmetricBindingBase.getProtectionOrder() == ProtectionOrder.EncryptBeforeSigning) {
                        throw new IllegalArgumentException(SPConstants.ERR_INVALID_POLICY);
                    }
                    asymmetricBindingBase.setProtectionOrder(protectionOrder);
                    continue;
                }
                
                QName encryptSignature = getVersion().getSPConstants().getEncryptSignature();
                if (encryptSignature.getLocalPart().equals(assertionName)
                    && encryptSignature.getNamespaceURI().equals(assertionNamespace)) {
                    if (asymmetricBindingBase.isEncryptSignature()) {
                        throw new IllegalArgumentException(SPConstants.ERR_INVALID_POLICY);
                    }
                    asymmetricBindingBase.setEncryptSignature(true);
                    continue;
                }
                
                QName protectTokens = getVersion().getSPConstants().getProtectTokens();
                if (protectTokens.getLocalPart().equals(assertionName)
                    && protectTokens.getNamespaceURI().equals(assertionNamespace)) {
                    if (asymmetricBindingBase.isProtectTokens()) {
                        throw new IllegalArgumentException(SPConstants.ERR_INVALID_POLICY);
                    }
                    asymmetricBindingBase.setProtectTokens(true);
                    continue;
                }
                
                QName onlySign = getVersion().getSPConstants().getOnlySignEntireHeadersAndBody(); 
                if (onlySign.getLocalPart().equals(assertionName)
                    && onlySign.getNamespaceURI().equals(assertionNamespace)) {
                    if (asymmetricBindingBase.isOnlySignEntireHeadersAndBody()) {
                        throw new IllegalArgumentException(SPConstants.ERR_INVALID_POLICY);
                    }
                    asymmetricBindingBase.setOnlySignEntireHeadersAndBody(true);
                    continue;
                }
            }
        }
    }

    public ProtectionOrder getProtectionOrder() {
        return protectionOrder;
    }

    protected void setProtectionOrder(ProtectionOrder protectionOrder) {
        this.protectionOrder = protectionOrder;
    }

    public boolean isEncryptSignature() {
        return encryptSignature;
    }

    protected void setEncryptSignature(boolean encryptSignature) {
        this.encryptSignature = encryptSignature;
    }

    public boolean isProtectTokens() {
        return protectTokens;
    }

    protected void setProtectTokens(boolean protectTokens) {
        this.protectTokens = protectTokens;
    }

    public boolean isOnlySignEntireHeadersAndBody() {
        return onlySignEntireHeadersAndBody;
    }

    protected void setOnlySignEntireHeadersAndBody(boolean onlySignEntireHeadersAndBody) {
        this.onlySignEntireHeadersAndBody = onlySignEntireHeadersAndBody;
    }
}
