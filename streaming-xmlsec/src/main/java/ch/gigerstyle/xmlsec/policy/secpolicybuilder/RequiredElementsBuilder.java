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
import ch.gigerstyle.xmlsec.policy.secpolicy.model.RequiredElements;
import org.apache.axiom.om.OMAttribute;
import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.OMNamespace;
import org.apache.neethi.Assertion;
import org.apache.neethi.AssertionBuilderFactory;
import org.apache.neethi.builders.AssertionBuilder;

import javax.xml.namespace.QName;
import java.util.Iterator;


public class RequiredElementsBuilder implements AssertionBuilder {

    private static final QName[] KNOWN_ELEMENTS = new QName[]{
            SP11Constants.REQUIRED_ELEMENTS,
            SP12Constants.REQUIRED_ELEMENTS,
            SP13Constants.REQUIRED_ELEMENTS
    };

    public Assertion build(OMElement element, AssertionBuilderFactory factory) throws IllegalArgumentException {

        SPConstants spConstants = PolicyUtil.getSPVersion(element.getQName().getNamespaceURI());

        RequiredElements requiredElements = new RequiredElements(spConstants);
        OMAttribute attrXPathVersion = element.getAttribute(spConstants.getAttrXpathVersion());

        if (attrXPathVersion != null) {
            requiredElements.setXPathVersion(attrXPathVersion.getAttributeValue());
        }

        for (Iterator iterator = element.getChildElements(); iterator.hasNext();) {
            processElement((OMElement) iterator.next(), requiredElements, spConstants);
        }

        return requiredElements;
    }

    public QName[] getKnownElements() {
        return KNOWN_ELEMENTS;
    }

    private void processElement(OMElement element, RequiredElements parent, SPConstants spConstants) {
        QName name = element.getQName();
        if (spConstants.getXpath().equals(name)) {
            parent.addXPathExpression(element.getText());
            Iterator namespaces = element.getAllDeclaredNamespaces();
            while (namespaces.hasNext()) {
                OMNamespace nm = (OMNamespace) namespaces.next();
                parent.addDeclaredNamespaces(nm.getNamespaceURI(), nm.getPrefix());
            }
        }
    }

}
