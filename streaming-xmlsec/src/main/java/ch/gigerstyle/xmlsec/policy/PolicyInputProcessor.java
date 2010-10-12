package ch.gigerstyle.xmlsec.policy;

import ch.gigerstyle.xmlsec.ext.*;
import ch.gigerstyle.xmlsec.impl.processor.input.PipedInputProcessor;
import ch.gigerstyle.xmlsec.securityEvent.*;

import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.XMLEvent;

/**
 * User: giger
 * Date: Sep 2, 2010
 * Time: 8:08:51 PM
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
public class PolicyInputProcessor extends AbstractInputProcessor {

    private PolicyEnforcer policyEnforcer;

    private XMLEvent deferredXMLEvent;

    public PolicyInputProcessor(PolicyEnforcer policyEnforcer, SecurityProperties securityProperties) {
        super(securityProperties);
        this.setPhase(Constants.Phase.POSTPROCESSING);
        this.getBeforeProcessors().add(PipedInputProcessor.class.getName());
        this.policyEnforcer = policyEnforcer;
    }

    @Override
    public void processEvent(XMLEvent xmlEvent, InputProcessorChain inputProcessorChain, SecurityContext securityContext) throws XMLStreamException, XMLSecurityException {
        if (xmlEvent.isStartElement()) {
            if (getLastStartElementName().equals(Constants.TAG_soap11_Body)) {
                OperationSecurityEvent operationSecurityEvent = new OperationSecurityEvent(SecurityEvent.Event.Operation);
                operationSecurityEvent.setOperation(xmlEvent.asStartElement().getName());
                policyEnforcer.registerSecurityEvent(operationSecurityEvent);
            }
        } else if (xmlEvent.isEndElement() && xmlEvent.asEndElement().getName().equals(Constants.TAG_soap11_Envelope)) {
            //hold the last XMLEvent back until the policy is verified
            deferredXMLEvent = xmlEvent;
            return;
        }

        //the following events are only interesting for policy verification. So call directly the policyEnforcer for these
        //test if non encrypted element not have to be encrypted per policy
        if (!securityContext.isInEncryptedContent()) {
            if (xmlEvent.isStartElement()) {
                //this could be a Element encryption...
                EncryptedElementSecurityEvent encryptedElementSecurityEvent = new EncryptedElementSecurityEvent(SecurityEvent.Event.EncryptedElement, true);
                encryptedElementSecurityEvent.setElement(xmlEvent.asStartElement().getName());
                policyEnforcer.registerSecurityEvent(encryptedElementSecurityEvent);

                //... or it could be a contentEncryption too...
                ContentEncryptedElementSecurityEvent contentEncryptedElementSecurityEvent = new ContentEncryptedElementSecurityEvent(SecurityEvent.Event.ContentEncrypted, true);
                contentEncryptedElementSecurityEvent.setElement(getLastStartElementName());
                policyEnforcer.registerSecurityEvent(contentEncryptedElementSecurityEvent);

                //todo special case EncryptedPart
                //if (xmlEvent.isStartElement && (level == 2 || (level == 1 && xmlEvent.asStartElement.getName.equals(Constants.TAG_soap_Body))) {
                //remove this if, the one above if is more correct
                if (xmlEvent.asStartElement().getName().equals(Constants.TAG_soap11_Body)) {
                    EncryptedPartSecurityEvent encryptedPartSecurityEvent = new EncryptedPartSecurityEvent(SecurityEvent.Event.EncryptedPart, true);
                    encryptedPartSecurityEvent.setElement(xmlEvent.asStartElement().getName());
                    policyEnforcer.registerSecurityEvent(encryptedPartSecurityEvent);
                }
                //}

            } else if (xmlEvent.isCharacters() || xmlEvent.isEntityReference() || xmlEvent.isProcessingInstruction()) {
                //can only be a content encryption
                ContentEncryptedElementSecurityEvent contentEncryptedElementSecurityEvent = new ContentEncryptedElementSecurityEvent(SecurityEvent.Event.ContentEncrypted, true);
                contentEncryptedElementSecurityEvent.setElement(getLastStartElementName());
                policyEnforcer.registerSecurityEvent(contentEncryptedElementSecurityEvent);
            }
        }

        //test if non signed element not have to be signed per policy
        if (!securityContext.isInSignedContent()) {
            if (xmlEvent.isStartElement()) {
                SignedElementSecurityEvent signedElementSecurityEvent = new SignedElementSecurityEvent(SecurityEvent.Event.SignedElement, true);
                signedElementSecurityEvent.setElement(xmlEvent.asStartElement().getName());
                policyEnforcer.registerSecurityEvent(signedElementSecurityEvent);

                //todo special case SignedPart
                //if (xmlEvent.isStartElement && (level == 2 || (level == 1 && xmlEvent.asStartElement.getName.equals(Constants.TAG_soap_Body))) {
                //remove this if, the one above if is more correct
                if (xmlEvent.asStartElement().getName().equals(Constants.TAG_soap11_Body)) {
                    SignedPartSecurityEvent signedPartSecurityEvent = new SignedPartSecurityEvent(SecurityEvent.Event.SignedPart, true);
                    signedPartSecurityEvent.setElement(xmlEvent.asStartElement().getName());
                    policyEnforcer.registerSecurityEvent(signedPartSecurityEvent);
                }
                //}
            }
        }

        inputProcessorChain.processEvent(xmlEvent);
    }

    @Override
    public void doFinal(InputProcessorChain inputProcessorChain, SecurityContext securityContext) throws XMLStreamException, XMLSecurityException {
        try {
            policyEnforcer.doFinal();
        } catch (PolicyViolationException e) {
            throw new XMLSecurityException(e);
        }
        //if the policy verifies we can push now the last element. 
        inputProcessorChain.processEvent(deferredXMLEvent);
        inputProcessorChain.reset();
        inputProcessorChain.doFinal();
    }
}
