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

import java.util.Iterator;

import javax.xml.namespace.QName;

import org.apache.axiom.om.OMAttribute;
import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.OMNamespace;
import org.apache.neethi.Assertion;
import org.apache.neethi.AssertionBuilderFactory;
import org.apache.neethi.builders.AssertionBuilder;
import org.apache.ws.secpolicy.SPConstants;
import org.apache.ws.secpolicy.SP11Constants;
import org.apache.ws.secpolicy.model.RequiredElements;

public class RequiredElementsBuilder implements AssertionBuilder<OMElement> {

    
    public Assertion build(OMElement element, AssertionBuilderFactory factory) throws IllegalArgumentException {
        
        RequiredElements requiredElements = new RequiredElements(SPConstants.SP_V11);
        OMAttribute attrXPathVersion = element.getAttribute(SP11Constants.ATTR_XPATH_VERSION);
        
        if (attrXPathVersion != null) {
            requiredElements.setXPathVersion(attrXPathVersion.getAttributeValue());
        }
        
        for (Iterator iterator = element.getChildElements(); iterator.hasNext();) {
            processElement((OMElement) iterator.next(),requiredElements);            
        }
        
        return requiredElements;
    }
        
    public QName[] getKnownElements() {
        return new QName[] {SP11Constants.REQUIRED_ELEMENTS};
    }

    private void processElement(OMElement element, RequiredElements parent) {
        QName name = element.getQName();
        if (SP11Constants.XPATH.equals(name)) {
            parent.addXPathExpression(element.getText());
            Iterator namespaces = element.getNamespacesInScope();
            while (namespaces.hasNext()) {
                OMNamespace nm = (OMNamespace) namespaces.next();
                parent.addDeclaredNamespaces(nm.getNamespaceURI(), nm.getPrefix());
            }
        }
    }
    
}
