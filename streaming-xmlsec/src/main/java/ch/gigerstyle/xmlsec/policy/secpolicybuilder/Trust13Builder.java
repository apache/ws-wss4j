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
package ch.gigerstyle.xmlsec.policy.secpolicybuilder;

import ch.gigerstyle.xmlsec.policy.secpolicy.PolicyUtil;
import ch.gigerstyle.xmlsec.policy.secpolicy.SP12Constants;
import ch.gigerstyle.xmlsec.policy.secpolicy.SP13Constants;
import ch.gigerstyle.xmlsec.policy.secpolicy.SPConstants;
import ch.gigerstyle.xmlsec.policy.secpolicy.model.Trust13;
import org.apache.axiom.om.OMElement;
import org.apache.neethi.Assertion;
import org.apache.neethi.AssertionBuilderFactory;
import org.apache.neethi.builders.AssertionBuilder;

import javax.xml.namespace.QName;


public class Trust13Builder implements AssertionBuilder {

    private static final QName[] KNOWN_ELEMENTS = new QName[]{
            SP12Constants.TRUST_13,
            SP13Constants.TRUST_13
    };

    public Assertion build(OMElement element, AssertionBuilderFactory factory)
            throws IllegalArgumentException {

        element = element.getFirstChildWithName(SPConstants.POLICY);

        if (element == null) {
            throw new IllegalArgumentException(
                    "Trust10 assertion doesn't contain any Policy");
        }

        SPConstants spConstants = PolicyUtil.getSPVersion(element.getQName().getNamespaceURI());

        Trust13 trust13 = new Trust13(spConstants);

        if (element
                .getFirstChildWithName(spConstants.getMustSupportClientChallenge()) != null) {
            trust13.setMustSupportClientChallenge(true);
        }

        if (element
                .getFirstChildWithName(spConstants.getMustSupportServerChallenge()) != null) {
            trust13.setMustSupportServerChallenge(true);
        }

        if (element.getFirstChildWithName(spConstants.getRequireClientEntropy()) != null) {
            trust13.setRequireClientEntropy(true);
        }

        if (element.getFirstChildWithName(spConstants.getRequireServerEntropy()) != null) {
            trust13.setRequireServerEntropy(true);
        }

        if (element.getFirstChildWithName(spConstants.getMustSupportIssuedTokens()) != null) {
            trust13.setMustSupportIssuedTokens(true);
        }

        if (element.getFirstChildWithName(spConstants.getRequireRequestSecurityTokenCollection()) != null) {
            trust13.setRequireRequestSecurityTokenCollection(true);
        }

        if (element.getFirstChildWithName(spConstants.getRequireAppliesTo()) != null) {
            trust13.setRequireAppliesTo(true);
        }

        return trust13;
    }

    public QName[] getKnownElements() {
        return KNOWN_ELEMENTS;
    }

}
