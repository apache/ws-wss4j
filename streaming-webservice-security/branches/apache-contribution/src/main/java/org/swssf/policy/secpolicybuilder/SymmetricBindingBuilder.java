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
import org.swssf.policy.secpolicy.model.AlgorithmSuite;
import org.swssf.policy.secpolicy.model.Layout;
import org.swssf.policy.secpolicy.model.ProtectionToken;
import org.swssf.policy.secpolicy.model.SymmetricBinding;

import javax.xml.namespace.QName;
import java.util.Iterator;
import java.util.List;

/**
 * class lent from apache rampart
 */
public class SymmetricBindingBuilder implements AssertionBuilder {

    private static final QName[] KNOWN_ELEMENTS = new QName[]{
            SP11Constants.SYMMETRIC_BINDING,
            SP12Constants.SYMMETRIC_BINDING,
            SP13Constants.SYMMETRIC_BINDING
    };

    public Assertion build(OMElement element, AssertionBuilderFactory factory) throws IllegalArgumentException {

        SPConstants spConstants = PolicyUtil.getSPVersion(element.getQName().getNamespaceURI());

        SymmetricBinding symmetricBinding = new SymmetricBinding(spConstants);

        Policy policy = PolicyEngine.getPolicy(element.getFirstElement());
        policy = (Policy) policy.normalize(false);

        for (Iterator iterator = policy.getAlternatives(); iterator.hasNext(); ) {
            processAlternatives((List) iterator.next(), symmetricBinding, spConstants);

            /*
            * since there should be only one alternative ..
            */
            break;
        }
        return symmetricBinding;
    }

    public QName[] getKnownElements() {
        return KNOWN_ELEMENTS;
    }

    private void processAlternatives(List assertions, SymmetricBinding symmetricBinding, SPConstants spConstants) {
        Assertion assertion;
        QName name;

        for (Iterator iterator = assertions.iterator(); iterator.hasNext(); ) {
            assertion = (Assertion) iterator.next();
            name = assertion.getName();

            if (spConstants.getAlgorithmSuite().equals(name)) {
                symmetricBinding.setAlgorithmSuite((AlgorithmSuite) assertion);

            } else if (spConstants.getLayout().equals(name)) {
                symmetricBinding.setLayout((Layout) assertion);

            } else if (spConstants.getIncludeTimestamp().equals(name)) {
                symmetricBinding.setIncludeTimestamp(true);

            } else if (spConstants.getProtectionToken().equals(name)) {
                symmetricBinding.setProtectionToken((ProtectionToken) assertion);

            } else if (spConstants.getEncryptBeforeSigning().equals(name)) {
                symmetricBinding.setProtectionOrder(SPConstants.ProtectionOrder.EncryptBeforeSigning);

            } else if (spConstants.getSignBeforeEncrypting().equals(name)) {
                symmetricBinding.setProtectionOrder(SPConstants.ProtectionOrder.SignBeforeEncrypting);

            } else if (spConstants.getOnlySignEntireHeadersAndBody().equals(name)) {
                symmetricBinding.setEntireHeadersAndBodySignatures(true);
            } else if (spConstants.getEncryptSignature().equals(name)) {
                symmetricBinding.setSignatureProtection(true);
            }
        }
    }
}
