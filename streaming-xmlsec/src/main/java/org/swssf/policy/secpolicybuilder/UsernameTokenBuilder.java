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
import org.swssf.policy.secpolicy.model.UsernameToken;
import org.apache.axiom.om.OMAttribute;
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
public class UsernameTokenBuilder implements AssertionBuilder {

    private static final QName[] KNOWN_ELEMENTS = new QName[]{
            SP11Constants.USERNAME_TOKEN,
            SP12Constants.USERNAME_TOKEN,
            SP13Constants.USERNAME_TOKEN
    };

    public Assertion build(OMElement element, AssertionBuilderFactory factory) throws IllegalArgumentException {

        SPConstants spConstants = PolicyUtil.getSPVersion(element.getQName().getNamespaceURI());

        UsernameToken usernameToken = new UsernameToken(spConstants);

        OMAttribute attribute = element.getAttribute(spConstants.getIncludeToken());

        if (attribute != null) {
            SPConstants.IncludeTokenType inclusion = spConstants.getInclusionFromAttributeValue(attribute.getAttributeValue());
            usernameToken.setInclusion(inclusion);
        }

        OMElement policyElement = element.getFirstElement();

        if (policyElement != null && policyElement.getQName().equals(org.apache.neethi.Constants.Q_ELEM_POLICY)) {

            Policy policy = PolicyEngine.getPolicy(element.getFirstElement());
            policy = (Policy) policy.normalize(false);

            for (Iterator iterator = policy.getAlternatives(); iterator.hasNext();) {
                processAlternative((List) iterator.next(), usernameToken, spConstants);

                /*
                * since there should be only one alternative
                */
                break;
            }
        }

        return usernameToken;
    }

    public QName[] getKnownElements() {
        return KNOWN_ELEMENTS;
    }

    private void processAlternative(List assertions, UsernameToken parent, SPConstants spConstants) {

        for (Iterator iterator = assertions.iterator(); iterator.hasNext();) {
            Assertion assertion = (Assertion) iterator.next();
            QName qname = assertion.getName();

            if (spConstants.getWssUsernameToken10().equals(qname)) {
                parent.setUseUTProfile10(true);
            } else if (spConstants.getWssUsernameToken11().equals(qname)) {
                parent.setUseUTProfile11(true);
            } else if (spConstants.getNoPassword().equals(qname)) {
                parent.setNoPassword(true);
            } else if (spConstants.getHashPassword().equals(qname)) {
                parent.setHashPassword(true);
            } else if (spConstants.getRequireDerivedKeys().equals(qname)) {
                parent.setDerivedKeys(true);
            } else if (spConstants.getRequireExplicitDerivedKeys().equals(qname)) {
                parent.setExplicitDerivedKeys(true);
            } else if (spConstants.getRequireImpliedDerivedKeys().equals(qname)) {
                parent.setImpliedDerivedKeys(true);
            }
        }
    }
}
