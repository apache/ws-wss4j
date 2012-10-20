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
import org.apache.neethi.PolicyComponent;
import org.apache.neethi.PolicyContainingAssertion;
import org.apache.ws.security.policy.SPConstants;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;
import java.util.*;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class Layout extends AbstractSecurityAssertion implements PolicyContainingAssertion {

    public enum LayoutType {
        Strict,
        Lax,
        LaxTsFirst,
        LaxTsLast;

        private static final Map<String, LayoutType> lookup = new HashMap<String, LayoutType>();

        static {
            for (LayoutType u : EnumSet.allOf(LayoutType.class))
                lookup.put(u.name(), u);
        }

        public static LayoutType lookUp(String name) {
            return lookup.get(name);
        }
    }

    private Policy nestedPolicy;
    private LayoutType layoutType = LayoutType.Lax;

    public Layout(SPConstants.SPVersion version, Policy nestedPolicy) {
        super(version);
        this.nestedPolicy = nestedPolicy;

        parseNestedPolicy(nestedPolicy, this);
    }

    @Override
    public Policy getPolicy() {
        return nestedPolicy;
    }

    @Override
    public QName getName() {
        return getVersion().getSPConstants().getLayout();
    }

    @Override
    public PolicyComponent normalize() {
        return super.normalize(getPolicy());
    }

    @Override
    public void serialize(XMLStreamWriter writer) throws XMLStreamException {
        super.serialize(writer, getPolicy());
    }

    @Override
    protected AbstractSecurityAssertion cloneAssertion(Policy nestedPolicy) {
        return new Layout(getVersion(), nestedPolicy);
    }

    protected void parseNestedPolicy(Policy nestedPolicy, Layout layout) {
        Iterator<List<Assertion>> alternatives = nestedPolicy.getAlternatives();
        //we just process the first alternative
        //this means that if we have a compact policy only the first alternative is visible
        //in contrary to a normalized policy where just one alternative exists
        if (alternatives.hasNext()) {
            List<Assertion> assertions = alternatives.next();
            for (int i = 0; i < assertions.size(); i++) {
                Assertion assertion = assertions.get(i);
                String assertionName = assertion.getName().getLocalPart();
                LayoutType layoutType = LayoutType.lookUp(assertionName);
                if (layoutType != null) {
                    layout.setLayoutType(layoutType);
                    continue;
                }
            }
        }
    }

    public LayoutType getLayoutType() {
        return layoutType;
    }

    protected void setLayoutType(LayoutType layoutType) {
        this.layoutType = layoutType;
    }
}
