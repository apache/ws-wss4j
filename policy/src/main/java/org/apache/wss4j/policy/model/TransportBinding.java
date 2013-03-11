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
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;
import java.util.Iterator;
import java.util.List;

public class TransportBinding extends AbstractBinding {

    private TransportToken transportToken;

    public TransportBinding(SPConstants.SPVersion version, Policy nestedPolicy) {
        super(version, nestedPolicy);

        parseNestedPolicy(nestedPolicy, this);
    }

    @Override
    public QName getName() {
        return getVersion().getSPConstants().getTransportBinding();
    }

    @Override
    protected AbstractSecurityAssertion cloneAssertion(Policy nestedPolicy) {
        return new TransportBinding(getVersion(), nestedPolicy);
    }

    protected void parseNestedPolicy(Policy nestedPolicy, TransportBinding transportBinding) {
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
                if (getVersion().getSPConstants().getTransportToken().getLocalPart().equals(assertionName)
                        && getVersion().getSPConstants().getTransportToken().getNamespaceURI().equals(assertionNamespace)) {
                    if (transportBinding.getTransportToken() != null) {
                        throw new IllegalArgumentException(SPConstants.ERR_INVALID_POLICY);
                    }
                    transportBinding.setTransportToken((TransportToken) assertion);
                    continue;
                }
            }
        }
    }

    @Override
    public void serialize(XMLStreamWriter writer) throws XMLStreamException {
        super.serialize(writer, getPolicy());
    }

    public TransportToken getTransportToken() {
        return transportToken;
    }

    protected void setTransportToken(TransportToken transportToken) {
        this.transportToken = transportToken;
    }
}
