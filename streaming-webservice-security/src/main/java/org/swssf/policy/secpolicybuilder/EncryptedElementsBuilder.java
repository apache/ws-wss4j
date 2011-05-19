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

import org.apache.axiom.om.OMAttribute;
import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.OMNamespace;
import org.apache.neethi.Assertion;
import org.apache.neethi.AssertionBuilderFactory;
import org.apache.neethi.builders.AssertionBuilder;
import org.swssf.policy.secpolicy.*;
import org.swssf.policy.secpolicy.model.SignedEncryptedElements;

import javax.xml.namespace.QName;
import java.util.Iterator;

/**
 * class lent from apache rampart
 */
public class EncryptedElementsBuilder implements AssertionBuilder {

    private static final QName[] KNOWN_ELEMENTS = new QName[]{
            SP11Constants.ENCRYPTED_ELEMENTS,
            SP12Constants.ENCRYPTED_ELEMENTS,
            SP13Constants.ENCRYPTED_ELEMENTS
    };

    public Assertion build(OMElement element, AssertionBuilderFactory factory) throws IllegalArgumentException {

        SPConstants spConstants = PolicyUtil.getSPVersion(element.getQName().getNamespaceURI());

        SignedEncryptedElements signedEncryptedElements = new SignedEncryptedElements(false, spConstants);

        OMAttribute attribute = element.getAttribute(spConstants.getAttrXpathVersion());
        if (attribute != null) {
            signedEncryptedElements.setXPathVersion(attribute.getAttributeValue());
        }

        for (Iterator iterator = element.getChildElements(); iterator.hasNext(); ) {
            processElement((OMElement) iterator.next(), signedEncryptedElements, spConstants);
        }

        return signedEncryptedElements;
    }


    public QName[] getKnownElements() {
        return KNOWN_ELEMENTS;
    }


    private void processElement(OMElement element, SignedEncryptedElements parent, SPConstants spConstants) {
        if (spConstants.getXpath().equals(element.getQName())) {
            parent.addXPathExpression(element.getText());
            Iterator namespaces = element.getAllDeclaredNamespaces();
            while (namespaces.hasNext()) {
                OMNamespace nm = (OMNamespace) namespaces.next();
                parent.addDeclaredNamespaces(nm.getNamespaceURI(), nm.getPrefix());
            }
        }
    }
}
