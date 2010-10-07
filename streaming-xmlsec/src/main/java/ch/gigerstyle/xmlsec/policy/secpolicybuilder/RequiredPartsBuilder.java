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
import ch.gigerstyle.xmlsec.policy.secpolicy.model.Header;
import ch.gigerstyle.xmlsec.policy.secpolicy.model.RequiredParts;
import org.apache.axiom.om.OMAttribute;
import org.apache.axiom.om.OMElement;
import org.apache.neethi.Assertion;
import org.apache.neethi.AssertionBuilderFactory;
import org.apache.neethi.builders.AssertionBuilder;

import javax.xml.namespace.QName;
import java.util.Iterator;


public class RequiredPartsBuilder implements AssertionBuilder {

    private static final QName[] KNOWN_ELEMENTS = new QName[]{
            SP12Constants.REQUIRED_PARTS,
            SP13Constants.REQUIRED_PARTS
    };

    public Assertion build(OMElement element, AssertionBuilderFactory factory) throws IllegalArgumentException {

        SPConstants spConstants = PolicyUtil.getSPVersion(element.getQName().getNamespaceURI());

        RequiredParts requiredParts = new RequiredParts(spConstants);

        for (Iterator iterator = element.getChildElements(); iterator.hasNext();) {
            processElement((OMElement) iterator.next(), requiredParts, spConstants);
        }

        return requiredParts;
    }

    public QName[] getKnownElements() {
        return KNOWN_ELEMENTS;
    }

    private void processElement(OMElement element, RequiredParts parent, SPConstants spConstants) {

        QName name = element.getQName();

        if (spConstants.getHeader().equals(name)) {
            Header header = new Header();

            OMAttribute nameAttribute = element.getAttribute(SPConstants.NAME);
            if (nameAttribute != null) {
                header.setName(nameAttribute.getAttributeValue());
            }

            OMAttribute namespaceAttribute = element.getAttribute(SPConstants.NAMESPACE);
            header.setNamespace(namespaceAttribute.getAttributeValue());

            parent.addHeader(header);

        }
    }
}
