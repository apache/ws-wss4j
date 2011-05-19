/*
 * Copyright 2001-2004 The Apache Software Foundation.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.swssf.policy.secpolicybuilder;

import org.apache.axiom.om.OMElement;
import org.apache.neethi.Assertion;
import org.apache.neethi.AssertionBuilderFactory;
import org.apache.neethi.Policy;
import org.apache.neethi.PolicyEngine;
import org.apache.neethi.builders.AssertionBuilder;
import org.swssf.policy.secpolicy.*;
import org.swssf.policy.secpolicy.model.Layout;

import javax.xml.namespace.QName;
import java.util.Iterator;
import java.util.List;

/**
 * class lent from apache rampart
 */
public class LayoutBuilder implements AssertionBuilder {

    private static final QName[] KNOWN_ELEMENTS = new QName[]{
            SP11Constants.LAYOUT,
            SP12Constants.LAYOUT,
            SP13Constants.LAYOUT
    };

    public Assertion build(OMElement element, AssertionBuilderFactory factory) throws IllegalArgumentException {

        SPConstants spConstants = PolicyUtil.getSPVersion(element.getQName().getNamespaceURI());

        Layout layout = new Layout(spConstants);

        Policy policy = PolicyEngine.getPolicy(element.getFirstElement());
        policy = (Policy) policy.normalize(false);

        for (Iterator iterator = policy.getAlternatives(); iterator.hasNext(); ) {
            processAlternative((List) iterator.next(), layout, spConstants);
            break; // there should be only one alternative
        }

        return layout;
    }

    public QName[] getKnownElements() {
        return KNOWN_ELEMENTS;
    }

    public void processAlternative(List assertions, Layout parent, SPConstants spConstants) {

        for (Iterator iterator = assertions.iterator(); iterator.hasNext(); ) {
            Assertion assertion = (Assertion) iterator.next();
            QName qname = assertion.getName();

            if (spConstants.getStrict().equals(qname)) {
                parent.setValue(SPConstants.LAYOUT_STRICT);
            } else if (spConstants.getLax().equals(qname)) {
                parent.setValue(SPConstants.LAYOUT_LAX);
            } else if (spConstants.getLaxtsfirst().equals(qname)) {
                parent.setValue(SPConstants.LAYOUT_LAX_TIMESTAMP_FIRST);
            } else if (spConstants.getLaxtslast().equals(qname)) {
                parent.setValue(SPConstants.LAYOUT_LAX_TIMESTAMP_LAST);
            }

        }
    }
}
