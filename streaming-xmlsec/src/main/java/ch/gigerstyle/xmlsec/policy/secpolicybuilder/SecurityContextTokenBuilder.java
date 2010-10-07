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
import ch.gigerstyle.xmlsec.policy.secpolicy.model.SecurityContextToken;
import org.apache.axiom.om.OMAttribute;
import org.apache.axiom.om.OMElement;
import org.apache.neethi.Assertion;
import org.apache.neethi.AssertionBuilderFactory;
import org.apache.neethi.builders.AssertionBuilder;

import javax.xml.namespace.QName;

public class SecurityContextTokenBuilder implements AssertionBuilder {

    private static final QName[] KNOWN_ELEMENTS = new QName[]{
            SP11Constants.SECURITY_CONTEXT_TOKEN,
            SP12Constants.SECURITY_CONTEXT_TOKEN,
            SP13Constants.SECURITY_CONTEXT_TOKEN
    };

    public Assertion build(OMElement element, AssertionBuilderFactory factory)
            throws IllegalArgumentException {

        SPConstants spConstants = PolicyUtil.getSPVersion(element.getQName().getNamespaceURI());

        SecurityContextToken contextToken = new SecurityContextToken(spConstants);

        OMAttribute includeAttr = element.getAttribute(spConstants.getIncludeToken());
        if (includeAttr != null) {
            SPConstants.IncludeTokenType inclusion = spConstants.getInclusionFromAttributeValue(includeAttr.getAttributeValue());
            contextToken.setInclusion(inclusion);
        }

        element = element.getFirstChildWithName(SPConstants.POLICY);

        if (element != null) {

            if (element.getFirstChildWithName(spConstants.getRequiredDerivedKeys()) != null) {
                contextToken.setDerivedKeys(true);
            }

            if (element
                    .getFirstChildWithName(spConstants.getRequireExternalUriRefernce()) != null) {
                contextToken.setRequireExternalUriRef(true);
            }

            if (element
                    .getFirstChildWithName(spConstants.getSc10SecurityContextToken()) != null) {
                contextToken.setSc10SecurityContextToken(true);
            }
        }

        return contextToken;
    }

    public QName[] getKnownElements() {
        return KNOWN_ELEMENTS;
    }

}
