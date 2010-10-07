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

import ch.gigerstyle.xmlsec.policy.secpolicy.*;
import ch.gigerstyle.xmlsec.policy.secpolicy.model.IssuedToken;
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

public class IssuedTokenBuilder implements AssertionBuilder {

    private static final QName[] KNOWN_ELEMENTS = new QName[]{
            SP11Constants.ISSUED_TOKEN,
            SP12Constants.ISSUED_TOKEN,
            SP13Constants.ISSUED_TOKEN
    };

    public Assertion build(OMElement element, AssertionBuilderFactory factory)
            throws IllegalArgumentException {

        SPConstants spConstants = PolicyUtil.getSPVersion(element.getQName().getNamespaceURI());

        IssuedToken issuedToken = new IssuedToken(spConstants);

        OMAttribute includeAttr = element.getAttribute(spConstants.getIncludeToken());
        if (includeAttr != null) {
            SPConstants.IncludeTokenType inclusion = spConstants.getInclusionFromAttributeValue(includeAttr.getAttributeValue());
            issuedToken.setInclusion(inclusion);
        }
        // Extract Issuer
        OMElement issuerElem = element.getFirstChildWithName(spConstants.getIssuer());

        if (issuerElem != null) {
            OMElement issuerEpr = issuerElem.getFirstChildWithName(new QName(AddressingConstants.Final.WSA_NAMESPACE, "Address"));

            //try the other addressing namespace
            if (issuerEpr == null) {
                issuerEpr = issuerElem.getFirstChildWithName(new QName(AddressingConstants.Submission.WSA_NAMESPACE, "Address"));
            }

            issuedToken.setIssuerEpr(issuerEpr);
        }

        //TODO check why this returns an Address element
        //iter = issuerElem.getChildrenWithLocalName("Metadata");

        if (issuerElem != null) {
            OMElement issuerMex = issuerElem.getFirstChildWithName(new QName(AddressingConstants.Final.WSA_NAMESPACE, "Metadata"));

            //try the other addressing namespace
            if (issuerMex == null) {
                issuerMex = issuerElem.getFirstChildWithName(new QName(AddressingConstants.Submission.WSA_NAMESPACE, "Metadata"));
            }

            issuedToken.setIssuerMex(issuerMex);
        }

        // Extract RSTTemplate
        OMElement rstTmplElem = element.getFirstChildWithName(spConstants.getRequestSecurityTokenTemplate());
        if (rstTmplElem != null) {
            issuedToken.setRstTemplate(rstTmplElem);
        }

        OMElement policyElement = element.getFirstChildWithName(org.apache.neethi.Constants.Q_ELEM_POLICY);

        if (policyElement != null) {

            Policy policy = PolicyEngine.getPolicy(policyElement);
            policy = (Policy) policy.normalize(false);

            for (Iterator iterator = policy.getAlternatives(); iterator
                    .hasNext();) {
                processAlternative((List) iterator.next(), issuedToken, spConstants);
                break; // since there should be only one alternative ..
            }
        }

        return issuedToken;
    }

    public QName[] getKnownElements() {
        return KNOWN_ELEMENTS;
    }

    private void processAlternative(List assertions, IssuedToken parent, SPConstants spConstants) {
        Assertion assertion;
        QName name;

        for (Iterator iterator = assertions.iterator(); iterator.hasNext();) {
            assertion = (Assertion) iterator.next();
            name = assertion.getName();

            if (spConstants.getRequiredDerivedKeys().equals(name)) {
                parent.setDerivedKeys(true);
            } else if (spConstants.getRequireExternalRefernce().equals(name)) {
                parent.setRequireExternalReference(true);
            } else if (spConstants.getRequireInternalRefernce().equals(name)) {
                parent.setRequireInternalReference(true);
            }
        }

    }
}
