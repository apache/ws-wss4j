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
import org.swssf.policy.secpolicy.model.*;
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
public class AsymmetricBindingBuilder implements AssertionBuilder {

    private static final QName[] KNOWN_ELEMENTS = new QName[]{
            SP11Constants.ASYMMETRIC_BINDING,
            SP12Constants.ASYMMETRIC_BINDING,
            SP13Constants.ASYMMETRIC_BINDING
    };

    public Assertion build(OMElement element, AssertionBuilderFactory factory) throws IllegalArgumentException {

        SPConstants spConstants = PolicyUtil.getSPVersion(element.getQName().getNamespaceURI());

        AsymmetricBinding asymmetricBinding = new AsymmetricBinding(spConstants);

        Policy policy = PolicyEngine.getPolicy(element.getFirstElement());
        policy = (Policy) policy.normalize(false);

        for (Iterator iterator = policy.getAlternatives(); iterator.hasNext();) {
            processAlternative((List) iterator.next(), asymmetricBinding, spConstants);

            /*
            * since there should be only one alternative
            */
            break;
        }

        return asymmetricBinding;
    }

    private void processAlternative(List assertions, AsymmetricBinding asymmetricBinding, SPConstants spConstants) {

        Assertion assertion;
        QName name;

        for (Iterator iterator = assertions.iterator(); iterator.hasNext();) {
            assertion = (Assertion) iterator.next();
            name = assertion.getName();

            if (spConstants.getInitiatorToken().equals(name)) {
                asymmetricBinding.setInitiatorToken((InitiatorToken) assertion);

            } else if (spConstants.getRecipientToken().equals(name)) {
                asymmetricBinding.setRecipientToken((RecipientToken) assertion);

            } else if (spConstants.getAlgorithmSuite().equals(name)) {
                asymmetricBinding.setAlgorithmSuite((AlgorithmSuite) assertion);

            } else if (spConstants.getLayout().equals(name)) {
                asymmetricBinding.setLayout((Layout) assertion);

            } else if (spConstants.getIncludeTimestamp().equals(name)) {
                asymmetricBinding.setIncludeTimestamp(true);

            } else if (spConstants.getEncryptBeforeSigning().equals(name)) {
                asymmetricBinding.setProtectionOrder(SPConstants.ProtectionOrder.EncryptBeforeSigning);

            } else if (spConstants.getSignBeforeEncrypting().equals(name)) {
                asymmetricBinding.setProtectionOrder(SPConstants.ProtectionOrder.SignBeforeEncrypting);

            } else if (spConstants.getEncryptSignature().equals(name)) {
                asymmetricBinding.setSignatureProtection(true);

            } else if (spConstants.getProtectTokens().equals(name)) {
                asymmetricBinding.setTokenProtection(true);

            } else if (spConstants.getOnlySignEntireHeadersAndBody().equals(name)) {
                asymmetricBinding.setEntireHeadersAndBodySignatures(true);
            }
        }
    }

    public QName[] getKnownElements() {
        return KNOWN_ELEMENTS;
    }

}
 