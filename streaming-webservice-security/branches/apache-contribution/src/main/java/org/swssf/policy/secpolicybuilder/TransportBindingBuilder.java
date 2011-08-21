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
package org.swssf.policy.secpolicybuilder;

import org.apache.axiom.om.OMElement;
import org.apache.neethi.Assertion;
import org.apache.neethi.AssertionBuilderFactory;
import org.apache.neethi.Policy;
import org.apache.neethi.PolicyEngine;
import org.apache.neethi.builders.AssertionBuilder;
import org.swssf.policy.secpolicy.*;
import org.swssf.policy.secpolicy.model.*;

import javax.xml.namespace.QName;
import java.util.Iterator;
import java.util.List;

/**
 * class lent from apache rampart
 */
public class TransportBindingBuilder implements AssertionBuilder {

    private static final QName[] KNOWN_ELEMENTS = new QName[]{
            SP11Constants.TRANSPORT_BINDING,
            SP12Constants.TRANSPORT_BINDING,
            SP13Constants.TRANSPORT_BINDING
    };

    public Assertion build(OMElement element, AssertionBuilderFactory factory) throws IllegalArgumentException {

        SPConstants spConstants = PolicyUtil.getSPVersion(element.getQName().getNamespaceURI());

        TransportBinding transportBinding = new TransportBinding(spConstants);

        Policy policy = PolicyEngine.getPolicy(element.getFirstElement());
        policy = (Policy) policy.normalize(false);

        for (Iterator iterator = policy.getAlternatives(); iterator.hasNext(); ) {
            processAlternative((List) iterator.next(), transportBinding, factory, spConstants);

            /*
            * since there should be only one alternative
            */
            break;
        }

        return transportBinding;
    }

    public QName[] getKnownElements() {
        return KNOWN_ELEMENTS;
    }

    private void processAlternative(List assertionList, TransportBinding parent, AssertionBuilderFactory factory, SPConstants spConstants) {

        for (Iterator iterator = assertionList.iterator(); iterator.hasNext(); ) {

            Assertion primitive = (Assertion) iterator.next();
            QName name = primitive.getName();

            if (name.equals(spConstants.getAlgorithmSuite())) {
                parent.setAlgorithmSuite((AlgorithmSuite) primitive);

            } else if (name.equals(spConstants.getTransportToken())) {
                parent.setTransportToken(((TransportToken) primitive));

            } else if (name.equals(spConstants.getIncludeTimestamp())) {
                parent.setIncludeTimestamp(true);

            } else if (name.equals(spConstants.getLayout())) {
                parent.setLayout((Layout) primitive);

            } else if (name.equals(spConstants.getSignedSupportingTokens())) {
                parent.setSignedSupportingToken((SupportingToken) primitive);

            } else if (name.equals(spConstants.getSignedEndorsingSupportingTokens())) {
                parent.setSignedEndorsingSupportingTokens((SupportingToken) primitive);
            }
        }
    }
}
