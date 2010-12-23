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
import ch.gigerstyle.xmlsec.policy.secpolicy.model.Header;
import ch.gigerstyle.xmlsec.policy.secpolicy.model.SignedEncryptedParts;
import org.apache.axiom.om.OMAttribute;
import org.apache.axiom.om.OMElement;
import org.apache.neethi.Assertion;
import org.apache.neethi.AssertionBuilderFactory;
import org.apache.neethi.builders.AssertionBuilder;

import javax.xml.namespace.QName;
import java.util.Iterator;

/**
 * class lent from apache rampart
 */
public class EncryptedPartsBuilder implements AssertionBuilder {

    private static final QName[] KNOWN_ELEMENTS = new QName[]{
            SP11Constants.ENCRYPTED_PARTS,
            SP12Constants.ENCRYPTED_PARTS,
            SP13Constants.ENCRYPTED_PARTS,
    };

    public Assertion build(OMElement element, AssertionBuilderFactory factory) throws IllegalArgumentException {

        SPConstants spConstants = PolicyUtil.getSPVersion(element.getQName().getNamespaceURI());

        SignedEncryptedParts signedEncryptedParts = new SignedEncryptedParts(false, spConstants);

        Iterator iterator = element.getChildElements();
        if (iterator.hasNext()) {
            for (; iterator.hasNext();) {
                processElement((OMElement) iterator.next(), signedEncryptedParts, spConstants);
            }
        } else {
            // If we have only <sp:EncryptedParts xmlns:sp="http://schemas.xmlsoap.org/ws/2005/07/securitypolicy"/>
            // then we need to encrypt the whole body (refer to http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702/ws-securitypolicy-1.2-spec-os.html#_Toc161826515).
            signedEncryptedParts.setBody(true);
        }

        return signedEncryptedParts;
    }

    public QName[] getKnownElements() {
        return KNOWN_ELEMENTS;
    }

    private void processElement(OMElement element, SignedEncryptedParts parent, SPConstants spConstants) {

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

        } else if (spConstants.getBody().equals(name)) {
            parent.setBody(true);
        }
    }
}
