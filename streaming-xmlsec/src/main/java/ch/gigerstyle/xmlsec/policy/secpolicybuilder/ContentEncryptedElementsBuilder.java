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
import ch.gigerstyle.xmlsec.policy.secpolicy.model.ContentEncryptedElements;
import org.apache.axiom.om.OMAttribute;
import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.OMNamespace;
import org.apache.neethi.Assertion;
import org.apache.neethi.AssertionBuilderFactory;
import org.apache.neethi.builders.AssertionBuilder;

import javax.xml.namespace.QName;
import java.util.Iterator;


public class ContentEncryptedElementsBuilder implements AssertionBuilder {

    private static final QName[] KNOWN_ELEMENTS = new QName[]{
            SP12Constants.CONTENT_ENCRYPTED_ELEMENTS,
            SP13Constants.CONTENT_ENCRYPTED_ELEMENTS
    };

    public Assertion build(OMElement element, AssertionBuilderFactory factory) throws IllegalArgumentException {

        SPConstants spConstants = PolicyUtil.getSPVersion(element.getQName().getNamespaceURI());

        ContentEncryptedElements contentEncryptedElements = new ContentEncryptedElements(spConstants);
        OMAttribute attrXPathVersion = element.getAttribute(spConstants.getAttrXpathVersion());

        if (attrXPathVersion != null) {
            contentEncryptedElements.setXPathVersion(attrXPathVersion.getAttributeValue());
        }

        for (Iterator iterator = element.getChildElements(); iterator.hasNext();) {
            processElement((OMElement) iterator.next(), contentEncryptedElements, spConstants);
        }

        return contentEncryptedElements;
    }

    private void processElement(OMElement element, ContentEncryptedElements parent, SPConstants spConstants) {
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

    public QName[] getKnownElements() {
        return KNOWN_ELEMENTS;
    }
}
