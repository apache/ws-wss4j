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
import org.apache.neethi.Assertion;
import org.apache.neethi.AssertionBuilderFactory;
import org.apache.neethi.Constants;
import org.apache.neethi.builders.AssertionBuilder;
import org.apache.ws.secpolicy.SP11Constants;
import org.apache.ws.secpolicy.SPConstants;
import org.apache.ws.secpolicy.model.Header;
import org.apache.ws.secpolicy.model.SignedEncryptedParts;

public class EncryptedPartsBuilder implements AssertionBuilder<OMElement> {
        
    public Assertion build(OMElement element, AssertionBuilderFactory factory) throws IllegalArgumentException {
        
        SignedEncryptedParts signedEncryptedParts = new SignedEncryptedParts(false, SPConstants.SP_V11);
        
        Iterator iterator = element.getChildElements();
		if (iterator.hasNext()) {
			for (; iterator.hasNext();) {
				processElement((OMElement) iterator.next(),
						signedEncryptedParts);
			}
		} else {
			// If we have only <sp:EncryptedParts xmlns:sp="http://schemas.xmlsoap.org/ws/2005/07/securitypolicy"/>
			// then we need to encrypt the whole body (refer to http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702/ws-securitypolicy-1.2-spec-os.html#_Toc161826515).
			signedEncryptedParts.setBody(true);
		}
		
		 OMAttribute isOptional = element
				.getAttribute(Constants.Q_ELEM_OPTIONAL_ATTR);
		if (isOptional != null) {
			signedEncryptedParts.setOptional(Boolean.valueOf(isOptional
					.getAttributeValue()).booleanValue());
		}
        
        return signedEncryptedParts;
    }
    
    public QName[] getKnownElements() {
        return new QName[] {SP11Constants.ENCRYPTED_PARTS};
    }

    private void processElement(OMElement element, SignedEncryptedParts parent) {
        
        QName name = element.getQName();
        
        if (SP11Constants.HEADER.equals(name)) {
            Header header = new Header();
            
            OMAttribute nameAttribute = element.getAttribute(SPConstants.NAME);
            if( nameAttribute != null ) {
                header.setName(nameAttribute.getAttributeValue());
            }
            
            OMAttribute namespaceAttribute = element.getAttribute(SPConstants.NAMESPACE);
            header.setNamespace(namespaceAttribute.getAttributeValue());
            
            parent.addHeader(header);
            
        } else if (SP11Constants.BODY.equals(name)) {
            parent.setBody(true);            
        }        
    }
}
