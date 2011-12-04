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
package org.apache.ws.secpolicy11.builders;

import org.apache.axiom.om.OMAttribute;
import org.apache.axiom.om.OMElement;
import org.apache.neethi.Assertion;
import org.apache.neethi.AssertionBuilderFactory;
import org.apache.neethi.builders.AssertionBuilder;
import org.apache.ws.secpolicy.SP11Constants;
import org.apache.ws.secpolicy.SPConstants;
import org.apache.ws.secpolicy.model.SecurityContextToken;

import javax.xml.namespace.QName;

public class SecurityContextTokenBuilder implements AssertionBuilder<OMElement> {

    public Assertion build(OMElement element, AssertionBuilderFactory factory)
            throws IllegalArgumentException {

        SecurityContextToken contextToken = new SecurityContextToken(SPConstants.SP_V11);

        OMAttribute  includeAttr = element.getAttribute(SP11Constants.INCLUDE_TOKEN);
        
        if(includeAttr != null) {
            int inclusion = SP11Constants.getInclusionFromAttributeValue(includeAttr.getAttributeValue());
            contextToken.setInclusion(inclusion);
        }

        element = element.getFirstChildWithName(SPConstants.POLICY);

        if (element != null) {

            if (element.getFirstChildWithName(SP11Constants.REQUIRE_DERIVED_KEYS) != null) {
                contextToken.setDerivedKeys(true);
            }

            if (element
                    .getFirstChildWithName(SP11Constants.REQUIRE_EXTERNAL_URI_REFERNCE) != null) {
                contextToken.setRequireExternalUriRef(true);
            }

            if (element
                    .getFirstChildWithName(SP11Constants.SC10_SECURITY_CONTEXT_TOKEN) != null) {
                contextToken.setSc10SecurityContextToken(true);
            }
        }

        return contextToken;
    }

    public QName[] getKnownElements() {
        return new QName[] {SP11Constants.SECURITY_CONTEXT_TOKEN};
    }

}
