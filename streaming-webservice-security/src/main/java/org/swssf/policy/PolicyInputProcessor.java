/**
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.swssf.policy;

import org.swssf.ext.*;
import org.swssf.impl.processor.input.SecurityHeaderInputProcessor;
import org.swssf.securityEvent.*;

import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.XMLEvent;

/**
 * Processor to generate SecurityEvents regarding not secured elements
 *
 * @author $Author: giger $
 * @version $Revision: 281 $ $Date: 2011-01-04 21:15:27 +0100 (Tue, 04 Jan 2011) $
 */
public class PolicyInputProcessor extends AbstractInputProcessor {

    private PolicyEnforcer policyEnforcer;

    public PolicyInputProcessor(PolicyEnforcer policyEnforcer, SecurityProperties securityProperties) {
        super(securityProperties);
        this.setPhase(Constants.Phase.POSTPROCESSING);
        this.getBeforeProcessors().add(SecurityHeaderInputProcessor.class.getName());
        this.policyEnforcer = policyEnforcer;
    }

    @Override
    public XMLEvent processNextHeaderEvent(InputProcessorChain inputProcessorChain) throws XMLStreamException, WSSecurityException {
        XMLEvent xmlEvent = inputProcessorChain.processHeaderEvent();
        //test if non encrypted element not have to be encrypted per policy
        if (!inputProcessorChain.getDocumentContext().isInEncryptedContent() && inputProcessorChain.getDocumentContext().isInSecurityHeader()) {
            testEncryptionPolicy(xmlEvent, inputProcessorChain);
        }
        return xmlEvent;
    }

    @Override
    public XMLEvent processNextEvent(InputProcessorChain inputProcessorChain) throws XMLStreamException, WSSecurityException {
        XMLEvent xmlEvent = inputProcessorChain.processEvent();

        if (xmlEvent.isStartElement()) {
            if (inputProcessorChain.getDocumentContext().getDocumentLevel() == 3 && inputProcessorChain.getDocumentContext().isInSOAPBody()) {
                OperationSecurityEvent operationSecurityEvent = new OperationSecurityEvent(SecurityEvent.Event.Operation);
                operationSecurityEvent.setOperation(xmlEvent.asStartElement().getName());
                policyEnforcer.registerSecurityEvent(operationSecurityEvent);
            }
        } else if (inputProcessorChain.getDocumentContext().getDocumentLevel() == 1
                && xmlEvent.isEndElement()
                //ns mismatch should be detected by the xml parser so a local-name equality check should be enough
                && xmlEvent.asEndElement().getName().getLocalPart().equals(Constants.TAG_soap_Envelope_LocalName)) {
            try {
                policyEnforcer.doFinal();
            } catch (PolicyViolationException e) {
                throw new WSSecurityException(WSSecurityException.INVALID_SECURITY, null, e);
            }
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
        return xmlEvent;
    }

    private void testEncryptionPolicy(XMLEvent xmlEvent, InputProcessorChain inputProcessorChain) throws WSSecurityException {
        //the following events are only interesting for policy verification. So call directly the policyEnforcer for these
        if (xmlEvent.isStartElement()) {

            if (inputProcessorChain.getDocumentContext().getDocumentLevel() == 3 && inputProcessorChain.getDocumentContext().isInSOAPHeader()) {
                EncryptedPartSecurityEvent encryptedPartSecurityEvent = new EncryptedPartSecurityEvent(SecurityEvent.Event.EncryptedPart, true);
                encryptedPartSecurityEvent.setElement(xmlEvent.asStartElement().getName());
                policyEnforcer.registerSecurityEvent(encryptedPartSecurityEvent);
            } else if (inputProcessorChain.getDocumentContext().getDocumentLevel() == 3 && inputProcessorChain.getDocumentContext().isInSOAPBody()) {
                EncryptedPartSecurityEvent encryptedPartSecurityEvent = new EncryptedPartSecurityEvent(SecurityEvent.Event.EncryptedPart, true);
                encryptedPartSecurityEvent.setElement(inputProcessorChain.getDocumentContext().getParentElement(xmlEvent.getEventType()));
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
}
