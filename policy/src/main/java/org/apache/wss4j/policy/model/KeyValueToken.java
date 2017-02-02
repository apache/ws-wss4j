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

public class KeyValueToken extends AbstractToken {

    private boolean rsaKeyValue;

    public KeyValueToken(SPConstants.SPVersion version, SPConstants.IncludeTokenType includeTokenType, 
                         Policy nestedPolicy) {
        super(version, includeTokenType, null, null, null, nestedPolicy);
        setIncludeTokenType(includeTokenType);

        parseNestedPolicy(nestedPolicy, this);
    }

    @Override
    public QName getName() {
        return getVersion().getSPConstants().getKeyValueToken();
    }
    
    @Override
    public boolean equals(Object object) {
        if (object == this) {
            return true;
        }
        if (!(object instanceof KeyValueToken)) {
            return false;
        }
        
        KeyValueToken that = (KeyValueToken)object;
        if (rsaKeyValue != that.rsaKeyValue) {
            return false;
        }
        
        return super.equals(object);
    }
    
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + Boolean.hashCode(rsaKeyValue);
        
        return 31 * result + super.hashCode();
    }

    @Override
    protected AbstractSecurityAssertion cloneAssertion(Policy nestedPolicy) {
        return new KeyValueToken(getVersion(), getIncludeTokenType(), nestedPolicy);
    }

    protected void parseNestedPolicy(Policy nestedPolicy, KeyValueToken keyValueToken) {
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
                
                QName rsaKeyValue = getVersion().getSPConstants().getRsaKeyValue();
                if (rsaKeyValue.getLocalPart().equals(assertionName)
                    && rsaKeyValue.getNamespaceURI().equals(assertionNamespace)) {
                    if (keyValueToken.isRsaKeyValue()) {
                        throw new IllegalArgumentException(SPConstants.ERR_INVALID_POLICY);
                    }
                    keyValueToken.setRsaKeyValue(true);
                    continue;
                }
            }
        }
    }

    public boolean isRsaKeyValue() {
        return rsaKeyValue;
    }

    protected void setRsaKeyValue(boolean rsaKeyValue) {
        this.rsaKeyValue = rsaKeyValue;
    }
}
