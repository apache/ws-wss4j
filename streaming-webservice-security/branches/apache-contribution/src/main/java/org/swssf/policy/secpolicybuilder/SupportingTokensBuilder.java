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
import org.swssf.policy.secpolicy.PolicyUtil;
import org.swssf.policy.secpolicy.SP12Constants;
import org.swssf.policy.secpolicy.SP13Constants;
import org.swssf.policy.secpolicy.SPConstants;
import org.swssf.policy.secpolicy.model.*;

import javax.xml.namespace.QName;
import java.util.Iterator;
import java.util.List;

/**
 * class lent from apache rampart
 */
public class SupportingTokensBuilder implements AssertionBuilder {

    private static final QName[] KNOWN_ELEMENTS = new QName[]{
            SP12Constants.SUPPORTING_TOKENS,
            SP12Constants.SIGNED_SUPPORTING_TOKENS,
            SP12Constants.ENDORSING_SUPPORTING_TOKENS,
            SP12Constants.SIGNED_ENDORSING_SUPPORTING_TOKENS,
            SP12Constants.ENCRYPTED_SUPPORTING_TOKENS,
            SP12Constants.SIGNED_ENCRYPTED_SUPPORTING_TOKENS,
            SP12Constants.ENDORSING_ENCRYPTED_SUPPORTING_TOKENS,
            SP12Constants.SIGNED_ENDORSING_ENCRYPTED_SUPPORTING_TOKENS,
            SP13Constants.SUPPORTING_TOKENS,
            SP13Constants.SIGNED_SUPPORTING_TOKENS,
            SP13Constants.ENDORSING_SUPPORTING_TOKENS,
            SP13Constants.SIGNED_ENDORSING_SUPPORTING_TOKENS,
            SP13Constants.ENCRYPTED_SUPPORTING_TOKENS,
            SP13Constants.SIGNED_ENCRYPTED_SUPPORTING_TOKENS,
            SP13Constants.ENDORSING_ENCRYPTED_SUPPORTING_TOKENS,
            SP13Constants.SIGNED_ENDORSING_ENCRYPTED_SUPPORTING_TOKENS
    };

    public Assertion build(OMElement element, AssertionBuilderFactory factory)
            throws IllegalArgumentException {

        SPConstants spConstants = PolicyUtil.getSPVersion(element.getQName().getNamespaceURI());

        QName name = element.getQName();
        SupportingToken supportingToken = null;

        if (spConstants.getSupportingTokens().equals(name)) {
            supportingToken = new SupportingToken(
                    SPConstants.SupportingTokenType.SUPPORTING, spConstants);
        } else if (spConstants.getSignedSupportingTokens().equals(name)) {
            supportingToken = new SupportingToken(
                    SPConstants.SupportingTokenType.SIGNED, spConstants);
        } else if (spConstants.getEndorsingSupportingTokens().equals(name)) {
            supportingToken = new SupportingToken(
                    SPConstants.SupportingTokenType.ENDORSING, spConstants);
        } else if (spConstants.getSignedEndorsingSupportingTokens().equals(name)) {
            supportingToken = new SupportingToken(
                    SPConstants.SupportingTokenType.SIGNED_ENDORSING, spConstants);
        } else if (spConstants.getEncryptedSupportingTokens().equals(name)) {
            supportingToken = new SupportingToken(
                    SPConstants.SupportingTokenType.ENCRYPTED, spConstants);
        } else if (spConstants.getSignedEncryptedSupportingTokens().equals(name)) {
            supportingToken = new SupportingToken(
                    SPConstants.SupportingTokenType.SIGNED_ENCRYPTED, spConstants);
        } else if (spConstants.getEndorsingEncryptedSupportingTokens().equals(name)) {
            supportingToken = new SupportingToken(
                    SPConstants.SupportingTokenType.ENDORSING_ENCRYPTED, spConstants);
        } else if (spConstants.getSignedEndorsingEncryptedSupportingTokens().equals(name)) {
            supportingToken = new SupportingToken(
                    SPConstants.SupportingTokenType.SIGNED_ENDORSING_ENCRYPTED, spConstants);
        }

        Policy policy = PolicyEngine.getPolicy(element.getFirstElement());
        policy = (Policy) policy.normalize(false);

        for (Iterator iterator = policy.getAlternatives(); iterator.hasNext(); ) {
            processAlternative((List) iterator.next(), supportingToken, spConstants);
            /*
             * for the moment we will say there should be only one alternative 
             */
            break;
        }

        return supportingToken;
    }

    public QName[] getKnownElements() {
        return KNOWN_ELEMENTS;
    }

    private void processAlternative(List assertions, SupportingToken supportingToken, SPConstants spConstants) {

        for (Iterator iterator = assertions.iterator(); iterator.hasNext(); ) {

            Assertion primitive = (Assertion) iterator.next();
            QName qname = primitive.getName();

            if (spConstants.getAlgorithmSuite().equals(qname)) {
                supportingToken.setAlgorithmSuite((AlgorithmSuite) primitive);

            } else if (spConstants.getSignedParts().equals(qname)) {
                supportingToken
                        .setSignedParts((SignedEncryptedParts) primitive);

            } else if (spConstants.getSignedElements().equals(qname)) {
                supportingToken
                        .setSignedElements((SignedEncryptedElements) primitive);

            } else if (spConstants.getEncryptedParts().equals(qname)) {
                supportingToken
                        .setEncryptedParts((SignedEncryptedParts) primitive);

            } else if (spConstants.getEncryptedElements().equals(qname)) {
                supportingToken
                        .setEncryptedElements((SignedEncryptedElements) primitive);

            } else if (primitive instanceof Token) {
                supportingToken.setToken((Token) primitive);
            }
        }
    }
}
