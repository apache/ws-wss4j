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
package org.apache.ws.secpolicy12.builders;

import java.util.Iterator;

import javax.xml.namespace.QName;

import org.apache.axiom.om.OMAttribute;
import org.apache.axiom.om.OMElement;
import org.apache.neethi.Assertion;
import org.apache.neethi.AssertionBuilderFactory;
import org.apache.neethi.Constants;
import org.apache.neethi.builders.AssertionBuilder;
import org.apache.ws.secpolicy.SPConstants;
import org.apache.ws.secpolicy.SP12Constants;
import org.apache.ws.secpolicy.model.Header;
import org.apache.ws.secpolicy.model.SignedEncryptedParts;

public class SignedPartsBuilder implements AssertionBuilder<OMElement> {
        
    public Assertion build(OMElement element, AssertionBuilderFactory factory) throws IllegalArgumentException {
        SignedEncryptedParts signedEncryptedParts = new SignedEncryptedParts(true, SPConstants.SP_V12);
        
        for (Iterator iterator = element.getChildElements(); iterator.hasNext();) {
            processElement((OMElement) iterator.next(), signedEncryptedParts);
        }
        
        OMAttribute isOptional = element.getAttribute(Constants.Q_ELEM_OPTIONAL_ATTR);
		if (isOptional != null) {
			signedEncryptedParts.setOptional(Boolean.valueOf(isOptional.getAttributeValue())
					.booleanValue());
		}

        //presense of <sp:SignedParts/> enforces the requirement for sign body and all the header blocks
        if(!element.getChildren().hasNext()){
            signedEncryptedParts.setBody(true);
            signedEncryptedParts.setSignAllHeaders(true);
        }
        
        return signedEncryptedParts;
    }
       
    public QName[] getKnownElements() {
        return new QName[] {SP12Constants.SIGNED_PARTS};
    }

    private void processElement(OMElement element, SignedEncryptedParts parent) {
        
        QName name = element.getQName();
        
        if (SP12Constants.HEADER.equals(name)) {
            Header header = new Header();
            
            OMAttribute nameAttribute = element.getAttribute(SPConstants.NAME);
            if( nameAttribute != null ) {
                header.setName(nameAttribute.getAttributeValue());
            }
            
            OMAttribute namespaceAttribute = element.getAttribute(SPConstants.NAMESPACE);
            header.setNamespace(namespaceAttribute.getAttributeValue());
            
            parent.addHeader(header);
            
        } else if (SP12Constants.BODY.equals(name)) {
            parent.setBody(true);            
        } else if (SPConstants.ATTACHMENTS.equals(name.getLocalPart())){
            parent.setAttachments(true);
        }
    }
}
