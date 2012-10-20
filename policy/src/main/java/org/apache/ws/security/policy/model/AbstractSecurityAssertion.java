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

import org.apache.neethi.*;
import org.apache.ws.security.policy.AssertionState;
import org.apache.ws.security.policy.SPConstants;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public abstract class AbstractSecurityAssertion implements Assertion {

    private boolean isOptional;
    private boolean isIgnorable;
    private boolean normalized = false;

    private SPConstants.SPVersion version;

    protected AbstractSecurityAssertion(SPConstants.SPVersion version) {
        this.version = version;
    }

    @Override
    public boolean isOptional() {
        return isOptional;
    }

    public void setOptional(boolean isOptional) {
        this.isOptional = isOptional;
    }

    @Override
    public boolean isIgnorable() {
        return isIgnorable;
    }

    public void setIgnorable(boolean isIgnorable) {
        this.isIgnorable = isIgnorable;
    }

    @Override
    public short getType() {
        return org.apache.neethi.Constants.TYPE_ASSERTION;
    }

    @Override
    public boolean equal(PolicyComponent policyComponent) {
        throw new UnsupportedOperationException();
    }

    public void setNormalized(boolean normalized) {
        this.normalized = normalized;
    }

    public boolean isNormalized() {
        return this.normalized;
    }

    @Override
    public PolicyComponent normalize() {
        Policy policy = new Policy();
        ExactlyOne exactlyOne = new ExactlyOne();
        policy.addPolicyComponent(exactlyOne);

        if (isOptional()) {
            exactlyOne.addPolicyComponent(new All());
        }

        AbstractSecurityAssertion a = clone(null);
        a.setNormalized(true);
        a.setOptional(false);

        All all = new All();
        all.addPolicyComponent(a);
        exactlyOne.addPolicyComponent(all);

        return policy;
    }

    public PolicyComponent normalize(Policy nestedPolicy) {
        Policy normalizedNestedPolicy = nestedPolicy.normalize(true);

        Policy policy = new Policy();
        ExactlyOne exactlyOne = new ExactlyOne();
        policy.addPolicyComponent(exactlyOne);

        if (isOptional()) {
            exactlyOne.addPolicyComponent(new All());
        }

        // for all alternatives in normalized nested policy
        Iterator<List<Assertion>> alternatives = normalizedNestedPolicy.getAlternatives();
        while (alternatives.hasNext()) {
            List<Assertion> alternative = alternatives.next();

            Policy ncp = new Policy(nestedPolicy.getPolicyRegistry(), nestedPolicy.getNamespace());
            ExactlyOne nceo = new ExactlyOne();
            ncp.addPolicyComponent(nceo);

            All nca = new All();
            nceo.addPolicyComponent(nca);
            nca.addPolicyComponents(alternative);

            AbstractSecurityAssertion a = clone(ncp);
            a.setNormalized(true);
            a.setOptional(false);

            All all = new All();
            all.addPolicyComponent(a);
            exactlyOne.addPolicyComponent(all);

        }
        return policy;
    }

    public SPConstants.SPVersion getVersion() {
        return version;
    }

    public void serialize(XMLStreamWriter writer, Policy nestedPolicy) throws XMLStreamException {
        writer.writeStartElement(getName().getPrefix(), getName().getLocalPart(), getName().getNamespaceURI());
        writer.writeNamespace(getName().getPrefix(), getName().getNamespaceURI());
        if (!isNormalized() && isOptional()) {
            writer.writeAttribute(Constants.ATTR_WSP, writer.getNamespaceContext().getNamespaceURI(Constants.ATTR_WSP), Constants.ATTR_OPTIONAL, "true");
        }
        if (isIgnorable()) {
            writer.writeAttribute(Constants.ATTR_WSP, writer.getNamespaceContext().getNamespaceURI(Constants.ATTR_WSP), Constants.ATTR_IGNORABLE, "true");
        }
        nestedPolicy.serialize(writer);
        writer.writeEndElement();
    }

    protected abstract AbstractSecurityAssertion cloneAssertion(Policy nestedPolicy);

    public AbstractSecurityAssertion clone(Policy nestedPolicy) {
        AbstractSecurityAssertion assertion = cloneAssertion(nestedPolicy);
        assertion.setIgnorable(isIgnorable());
        assertion.setNormalized(isNormalized());
        assertion.setOptional(isOptional());
        return assertion;
    }

    public boolean isAsserted(Map<QName, List<AssertionState>> assertionStatesMap) {
        List<AssertionState> assertionStateList = assertionStatesMap.get(getName());
        for (int i = 0; i < assertionStateList.size(); i++) {
            AssertionState assertionState = assertionStateList.get(i);
            if (assertionState.getAssertion() == this && !assertionState.isAsserted()) {
                return false;
            }
        }
        return true;
    }
}
