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
import org.apache.neethi.PolicyContainingAssertion;
import org.apache.wss4j.policy.SPConstants;
import org.apache.wss4j.policy.SPConstants.SPVersion;

import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;
import java.util.Iterator;
import java.util.List;

public abstract class AbstractBinding extends AbstractSecurityAssertion implements PolicyContainingAssertion {

    private Policy nestedPolicy;
    private AlgorithmSuite algorithmSuite;
    private Layout layout;
    private boolean includeTimestamp;

    protected AbstractBinding(SPConstants.SPVersion version, Policy nestedPolicy) {
        super(version);
        this.nestedPolicy = nestedPolicy;
        parseNestedBindingPolicy(nestedPolicy, this);
        if (layout == null) {
            layout = new Layout(version, new Policy());
        }
    }

    @Override
    public Policy getPolicy() {
        return nestedPolicy;
    }

    @Override
    public boolean equals(Object object) {
        if (object == this) {
            return true;
        }

        if (!(object instanceof AbstractBinding)) {
            return false;
        }

        AbstractBinding that = (AbstractBinding)object;
        if (algorithmSuite != null && !algorithmSuite.equals(that.algorithmSuite)
            || algorithmSuite == null && that.algorithmSuite != null) {
            return false;
        }

        if (layout != null && !layout.equals(that.layout)
            || layout == null && that.layout != null) {
            return false;
        }

        if (includeTimestamp != that.includeTimestamp) {
            return false;
        }

        return super.equals(object);
    }

    @Override
    public int hashCode() {
        int result = 17;
        if (algorithmSuite != null) {
            result = 31 * result + algorithmSuite.hashCode();
        }
        if (layout != null) {
            result = 31 * result + layout.hashCode();
        }
        result = 31 * result + Boolean.hashCode(includeTimestamp);

        return 31 * result + super.hashCode();
    }

    @Override
    public PolicyComponent normalize() {
        return super.normalize(getPolicy());
    }

    @Override
    public void serialize(XMLStreamWriter writer) throws XMLStreamException {
        super.serialize(writer, getPolicy());
    }

    protected void parseNestedBindingPolicy(Policy nestedPolicy, AbstractBinding binding) {
        Iterator<List<Assertion>> alternatives = nestedPolicy.getAlternatives();
        //we just process the first alternative
        //this means that if we have a compact policy only the first alternative is visible
        //in contrary to a normalized policy where just one alternative exists
        if (alternatives.hasNext()) {
            List<Assertion> assertions = alternatives.next();
            for (int i = 0; i < assertions.size(); i++) {
                Assertion assertion = assertions.get(i);
                String assertionName = assertion.getName().getLocalPart();
                if (SPConstants.ALGORITHM_SUITE.equals(assertionName)) {
                    if (binding.getAlgorithmSuite() != null) {
                        throw new IllegalArgumentException(SPConstants.ERR_INVALID_POLICY);
                    }
                    binding.setAlgorithmSuite((AlgorithmSuite) assertion);
                    continue;
                }
                if (SPConstants.LAYOUT.equals(assertionName)) {
                    if (binding.getLayout() != null) {
                        throw new IllegalArgumentException(SPConstants.ERR_INVALID_POLICY);
                    }
                    Layout layout = (Layout) assertion;
                    binding.setLayout(layout);
                    if (layout.getLayoutType() == Layout.LayoutType.LaxTsFirst
                            || layout.getLayoutType() == Layout.LayoutType.LaxTsLast) {
                        binding.setIncludeTimestamp(true);
                    }
                    continue;
                }
                if (SPConstants.INCLUDE_TIMESTAMP.equals(assertionName)) {
                    binding.setIncludeTimestamp(true);
                    continue;
                }
            }
        }
        if (binding.getAlgorithmSuite() == null && binding.getVersion() != SPVersion.SP11) {
            throw new IllegalArgumentException("sp:" + getName().getLocalPart()
                                               + " must have an inner sp:AlgorithmSuite element");
        }
    }

    public AlgorithmSuite getAlgorithmSuite() {
        return algorithmSuite;
    }

    protected void setAlgorithmSuite(AlgorithmSuite algorithmSuite) {
        this.algorithmSuite = algorithmSuite;
    }

    public Layout getLayout() {
        return layout;
    }

    protected void setLayout(Layout layout) {
        this.layout = layout;
    }

    public boolean isIncludeTimestamp() {
        return includeTimestamp;
    }

    protected void setIncludeTimestamp(boolean includeTimestamp) {
        this.includeTimestamp = includeTimestamp;
    }
}
