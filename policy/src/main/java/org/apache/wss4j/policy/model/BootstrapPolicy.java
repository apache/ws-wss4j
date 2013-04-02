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

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;

import org.apache.neethi.Policy;
import org.apache.wss4j.policy.SPConstants.SPVersion;

/**
 * A BootstrapPolicy is held internally to a SecureConversationToken
 * 
 * While a BootstrapPolicy element DOES contain an internal Policy, this
 * token is NOT considered a PolicyContainingAssertion for the purpose of 
 * calculating things like normalized policies and vocabulary.
 */
public class BootstrapPolicy extends AbstractSecurityAssertion {
    private final Policy nestedPolicy;
    
    public BootstrapPolicy(SPVersion version, Policy nestedPolicy) {
        super(version);
        this.nestedPolicy = nestedPolicy;
    }

    public QName getName() {
        return super.getVersion().getSPConstants().getBootstrapPolicy();
    }
    
    public Policy getPolicy() {
        return nestedPolicy;
    }

    public void serialize(XMLStreamWriter writer) throws XMLStreamException {
        super.serialize(writer, nestedPolicy);
    }

    protected AbstractSecurityAssertion cloneAssertion(Policy nestedPolicy) {
        return this;
    }

}
