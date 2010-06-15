package ch.gigerstyle.xmlsec.processorImpl;

import ch.gigerstyle.xmlsec.*;
import org.w3._2000._09.xmldsig_.ReferenceType;
import org.w3._2000._09.xmldsig_.SignatureType;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.Attribute;
import javax.xml.stream.events.EndElement;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;
import java.util.*;

/**
 * User: giger
 * Date: May 14, 2010
 * Time: 2:36:01 PM
 * Copyright 2010 Marc Giger gigerstyle@gmx.ch
 * <p/>
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 * <p/>
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * <p/>
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */
public class SignatureReferenceVerifyInputProcessor extends AbstractInputProcessor {

    private SignatureType signatureType;

    private Map<QName, SignatureReferenceVerifier> signatureReferenceVerifiers = new HashMap<QName, SignatureReferenceVerifier>();

    public SignatureReferenceVerifyInputProcessor(SignatureType signatureType, SecurityProperties securityProperties) {
        super(securityProperties);
        this.signatureType = signatureType;
    }

    public void processEvent(XMLEvent xmlEvent, InputProcessorChain inputProcessorChain, SecurityContext securityContext) throws XMLStreamException, XMLSecurityException {
        if (xmlEvent.isStartElement()) {
            StartElement startElement = xmlEvent.asStartElement();

            Attribute refId = startElement.getAttributeByName(Constants.ATT_wsu_Id);
            if (refId != null) {
                List<ReferenceType> references = signatureType.getSignedInfo().getReference();
                for (int i = 0; i < references.size(); i++) {
                    ReferenceType referenceType =  references.get(i);
                    if (refId.getValue().equals(referenceType.getURI())) {
                        System.out.println("found " + refId.getValue());
                        //todo exception when reference is not found
                        signatureReferenceVerifiers.put(getLastStartElementName(), new SignatureReferenceVerifier(referenceType));
                    }
                }
            }            
        }

        Set<Map.Entry<QName, SignatureReferenceVerifier>> entrySet = signatureReferenceVerifiers.entrySet();
        for (Iterator<Map.Entry<QName, SignatureReferenceVerifier>> entryIterator = entrySet.iterator(); entryIterator.hasNext();) {
            Map.Entry<QName, SignatureReferenceVerifier> qNameSignatureReferenceVerifierEntry = entryIterator.next();
            qNameSignatureReferenceVerifierEntry.getValue().processEvent(xmlEvent);
        }

        if (xmlEvent.isEndElement()) {
            EndElement endElement = xmlEvent.asEndElement();
            if (signatureReferenceVerifiers.containsKey(endElement.getName())) {
                SignatureReferenceVerifier signatureReferenceVerifier = signatureReferenceVerifiers.remove(endElement.getName());
                signatureReferenceVerifier.doFinal();
            }
        }

        inputProcessorChain.processEvent(xmlEvent);
    }
}
