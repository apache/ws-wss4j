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

import org.swssf.policy.secpolicy.*;
import org.swssf.policy.secpolicy.model.Wss10;
import org.apache.axiom.om.OMElement;
import org.apache.neethi.Assertion;
import org.apache.neethi.AssertionBuilderFactory;
import org.apache.neethi.Policy;
import org.apache.neethi.PolicyEngine;
import org.apache.neethi.builders.AssertionBuilder;

import javax.xml.namespace.QName;
import java.util.Iterator;
import java.util.List;

/**
 * class lent from apache rampart
 */
public class WSS10Builder implements AssertionBuilder {

    private static final QName[] KNOWN_ELEMENTS = new QName[]{
            SP11Constants.WSS10,
            SP12Constants.WSS10,
            SP13Constants.WSS10
    };

    public Assertion build(OMElement element, AssertionBuilderFactory factory)
            throws IllegalArgumentException {

        SPConstants spConstants = PolicyUtil.getSPVersion(element.getQName().getNamespaceURI());

        Wss10 wss10 = new Wss10(spConstants);

        Policy policy = PolicyEngine.getPolicy(element.getFirstElement());
        policy = (Policy) policy.normalize(false);

        for (Iterator iterator = policy.getAlternatives(); iterator.hasNext();) {
            processAlternative((List) iterator.next(), wss10, spConstants);
            /*
             * since there should be only one alternative
             */
            break;
        }

        return wss10;
    }

    public QName[] getKnownElements() {
        return KNOWN_ELEMENTS;
    }

    private void processAlternative(List assertions, Wss10 parent, SPConstants spConstants) {

        Assertion assertion;
        QName name;

        for (Iterator iterator = assertions.iterator(); iterator.hasNext();) {
            assertion = (Assertion) iterator.next();
            name = assertion.getName();

            if (spConstants.getMustSupportRefKeyIdentifier().equals(name)) {
                parent.setMustSupportRefKeyIdentifier(true);

            } else if (spConstants.getMustSupportRefIssuerSerial().equals(name)) {
                parent.setMustSupportRefIssuerSerial(true);

            } else if (spConstants.getMustSupportRefExternalUri().equals(name)) {
                parent.setMustSupportRefExternalURI(true);

            } else if (spConstants.getMustSupportRefEmbeddedToken().equals(name)) {
                parent.setMustSupportRefEmbeddedToken(true);
            }
        }
    }
}
