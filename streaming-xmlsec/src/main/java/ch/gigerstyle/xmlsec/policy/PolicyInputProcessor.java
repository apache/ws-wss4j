package ch.gigerstyle.xmlsec.policy;

import ch.gigerstyle.xmlsec.ext.*;
import ch.gigerstyle.xmlsec.impl.processor.input.SecurityHeaderInputProcessor;
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
        this.getBeforeProcessors().add(SecurityHeaderInputProcessor.InternalSecurityHeaderProcessor.class.getName());
        this.policyEnforcer = policyEnforcer;
    }

    @Override
    public void processSecurityHeaderEvent(XMLEvent xmlEvent, InputProcessorChain inputProcessorChain) throws XMLStreamException, XMLSecurityException {

        //test if non encrypted element not have to be encrypted per policy
        if (!inputProcessorChain.getDocumentContext().isInEncryptedContent() && inputProcessorChain.getDocumentContext().isInSecurityHeader()) {
            testEncryptionPolicy(xmlEvent, inputProcessorChain);
        }
        super.processSecurityHeaderEvent(xmlEvent, inputProcessorChain);
    }

    @Override
    public void processEvent(XMLEvent xmlEvent, InputProcessorChain inputProcessorChain) throws XMLStreamException, XMLSecurityException {
        if (xmlEvent.isStartElement()) {
            if (inputProcessorChain.getDocumentContext().getDocumentLevel() == 3 && inputProcessorChain.getDocumentContext().isInSOAPBody()
                    && Constants.TAG_soap11_Body.equals(inputProcessorChain.getDocumentContext().getParentElement(xmlEvent.getEventType()))) {

                OperationSecurityEvent operationSecurityEvent = new OperationSecurityEvent(SecurityEvent.Event.Operation);
                operationSecurityEvent.setOperation(xmlEvent.asStartElement().getName());
                policyEnforcer.registerSecurityEvent(operationSecurityEvent);
            }
        } else if (xmlEvent.isEndElement() && xmlEvent.asEndElement().getName().equals(Constants.TAG_soap11_Envelope)) {
            //hold the last XMLEvent back until the policy is verified
            deferredXMLEvent = xmlEvent;
            return;
        }

        //test if non encrypted element not have to be encrypted per policy
        if (!inputProcessorChain.getDocumentContext().isInEncryptedContent() && !inputProcessorChain.getDocumentContext().isInSecurityHeader()) {
            testEncryptionPolicy(xmlEvent, inputProcessorChain);
        }

        //test if non signed element not have to be signed per policy
        if (!inputProcessorChain.getDocumentContext().isInSignedContent()) {
            if (xmlEvent.isStartElement()) {

                if (inputProcessorChain.getDocumentContext().getDocumentLevel() == 3 && inputProcessorChain.getDocumentContext().isInSOAPHeader()) {
                    SignedPartSecurityEvent signedPartSecurityEvent = new SignedPartSecurityEvent(SecurityEvent.Event.SignedPart, true);
                    signedPartSecurityEvent.setElement(xmlEvent.asStartElement().getName());
                    policyEnforcer.registerSecurityEvent(signedPartSecurityEvent);
                } else if (inputProcessorChain.getDocumentContext().getDocumentLevel() == 2 && inputProcessorChain.getDocumentContext().isInSOAPBody()) {
                    SignedPartSecurityEvent signedPartSecurityEvent = new SignedPartSecurityEvent(SecurityEvent.Event.SignedPart, true);
                    signedPartSecurityEvent.setElement(xmlEvent.asStartElement().getName());
                    policyEnforcer.registerSecurityEvent(signedPartSecurityEvent);
                } else if (inputProcessorChain.getDocumentContext().getDocumentLevel() > 3) {
                    SignedElementSecurityEvent signedElementSecurityEvent = new SignedElementSecurityEvent(SecurityEvent.Event.SignedElement, true);
                    signedElementSecurityEvent.setElement(xmlEvent.asStartElement().getName());
                    policyEnforcer.registerSecurityEvent(signedElementSecurityEvent);
                }
            }
        }

        inputProcessorChain.processEvent(xmlEvent);
    }

    private void testEncryptionPolicy(XMLEvent xmlEvent, InputProcessorChain inputProcessorChain) throws XMLSecurityException {
        //the following events are only interesting for policy verification. So call directly the policyEnforcer for these
        if (xmlEvent.isStartElement()) {

            if (inputProcessorChain.getDocumentContext().getDocumentLevel() == 3 && inputProcessorChain.getDocumentContext().isInSOAPHeader()) {
                EncryptedPartSecurityEvent encryptedPartSecurityEvent = new EncryptedPartSecurityEvent(SecurityEvent.Event.EncryptedPart, true);
                encryptedPartSecurityEvent.setElement(xmlEvent.asStartElement().getName());
                policyEnforcer.registerSecurityEvent(encryptedPartSecurityEvent);
            } else if (inputProcessorChain.getDocumentContext().getDocumentLevel() == 2 && inputProcessorChain.getDocumentContext().isInSOAPBody()) {
                EncryptedPartSecurityEvent encryptedPartSecurityEvent = new EncryptedPartSecurityEvent(SecurityEvent.Event.EncryptedPart, true);
                encryptedPartSecurityEvent.setElement(xmlEvent.asStartElement().getName());
                policyEnforcer.registerSecurityEvent(encryptedPartSecurityEvent);
            } else if (inputProcessorChain.getDocumentContext().getDocumentLevel() > 3) {
                EncryptedElementSecurityEvent encryptedElementSecurityEvent = new EncryptedElementSecurityEvent(SecurityEvent.Event.EncryptedElement, true);
                encryptedElementSecurityEvent.setElement(xmlEvent.asStartElement().getName());
                policyEnforcer.registerSecurityEvent(encryptedElementSecurityEvent);

                //... or it could be a contentEncryption too...
                ContentEncryptedElementSecurityEvent contentEncryptedElementSecurityEvent = new ContentEncryptedElementSecurityEvent(SecurityEvent.Event.ContentEncrypted, true);
                contentEncryptedElementSecurityEvent.setElement(inputProcessorChain.getDocumentContext().getParentElement(xmlEvent.getEventType()));
                policyEnforcer.registerSecurityEvent(contentEncryptedElementSecurityEvent);
            }

        } else if (xmlEvent.isCharacters() || xmlEvent.isEntityReference() || xmlEvent.isProcessingInstruction()) {
            //can only be a content encryption
            ContentEncryptedElementSecurityEvent contentEncryptedElementSecurityEvent = new ContentEncryptedElementSecurityEvent(SecurityEvent.Event.ContentEncrypted, true);
            contentEncryptedElementSecurityEvent.setElement(inputProcessorChain.getDocumentContext().getParentElement(xmlEvent.getEventType()));
            policyEnforcer.registerSecurityEvent(contentEncryptedElementSecurityEvent);
        }
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
