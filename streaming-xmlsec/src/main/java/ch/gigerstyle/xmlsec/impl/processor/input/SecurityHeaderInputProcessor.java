package ch.gigerstyle.xmlsec.impl.processor.input;

import ch.gigerstyle.xmlsec.ext.*;
import ch.gigerstyle.xmlsec.impl.util.FiFoQueue;

import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.EndElement;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;

/**
 * User: giger
 * Date: Jun 23, 2010
 * Time: 9:32:17 PM
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
public class SecurityHeaderInputProcessor extends AbstractInputProcessor {

    private FiFoQueue<XMLEvent> xmlEventList = new FiFoQueue<XMLEvent>();
    private InternalSecurityHeaderProcessor internalSecurityHeaderProcessor;
    private int countOfEventsToResponsibleSecurityHeader = 0;

    public SecurityHeaderInputProcessor(SecurityProperties securityProperties, InputProcessorChain inputProcessorChain) {
        super(securityProperties);
        setPhase(Constants.Phase.PREPROCESSING);

        internalSecurityHeaderProcessor = new InternalSecurityHeaderProcessor(securityProperties);
        inputProcessorChain.addProcessor(internalSecurityHeaderProcessor);
    }

    @Override
    public void processEvent(XMLEvent xmlEvent, InputProcessorChain inputProcessorChain) throws XMLStreamException, XMLSecurityException {

        //todo multiple security headers, actors etc

        if (xmlEvent.isStartElement()) {
            StartElement startElement = xmlEvent.asStartElement();
            if (inputProcessorChain.getDocumentContext().getDocumentLevel() == 3
                    && inputProcessorChain.getDocumentContext().isInSOAPHeader()
                    && startElement.getName().equals(Constants.TAG_wsse_Security)) {
                inputProcessorChain.getDocumentContext().setInSecurityHeader(true);
            }
            if (inputProcessorChain.getDocumentContext().getDocumentLevel() == 4
                    && inputProcessorChain.getDocumentContext().isInSecurityHeader()) {
                engageProcessor(inputProcessorChain, startElement, getSecurityProperties());
            }
        }

        if (inputProcessorChain.getDocumentContext().isInSecurityHeader()) {
            inputProcessorChain.processSecurityHeaderEvent(xmlEvent);
        } else {
            xmlEventList.enqueue(xmlEvent);
            countOfEventsToResponsibleSecurityHeader++;
        }

        if (xmlEvent.isEndElement()) {
            EndElement endElement = xmlEvent.asEndElement();
            if (inputProcessorChain.getDocumentContext().getDocumentLevel() == 3
                    && endElement.getName().equals(Constants.TAG_wsse_Security)) {
                inputProcessorChain.getDocumentContext().setInSecurityHeader(false);
                inputProcessorChain.removeProcessor(internalSecurityHeaderProcessor);

                InputProcessorChain subInputProcessorChain = inputProcessorChain.createSubChain(this);
                //since we are replaying the whole envelope strip the path:
                subInputProcessorChain.getDocumentContext().getPath().clear();
                //replay all events in "normal" processing chain
                int eventCount = 0;
                while (!xmlEventList.isEmpty()) {
                    XMLEvent event = xmlEventList.dequeue();
                    if (eventCount == countOfEventsToResponsibleSecurityHeader) {
                        subInputProcessorChain.getDocumentContext().setInSecurityHeader(true);
                    }
                    subInputProcessorChain.reset();
                    subInputProcessorChain.processEvent(event);
                    eventCount++;
                }

                countOfEventsToResponsibleSecurityHeader = 0;
                subInputProcessorChain.getDocumentContext().setInSecurityHeader(false);

                //remove this processor from chain now. the next events will go directly to the other processors
                inputProcessorChain.removeProcessor(this);
            }
        }
    }

    //todo move this method. DecryptProcessor should not have a dependency to this processor
    //this must be configurable in a xml file. Create a class that looks up the responsible processor

    public static void engageProcessor(InputProcessorChain inputProcessorChain, StartElement startElement, SecurityProperties securityProperties) {
        if (startElement.getName().equals(Constants.TAG_wsse_BinarySecurityToken)) {
            inputProcessorChain.addProcessor(new BinarySecurityTokenInputProcessor(securityProperties));
        } else if (startElement.getName().equals(Constants.TAG_xenc_EncryptedKey)) {
            inputProcessorChain.addProcessor(new EncryptedKeyInputProcessor(securityProperties));
        } else if (startElement.getName().equals(Constants.TAG_dsig_Signature)) {
            inputProcessorChain.addProcessor(new SignatureInputProcessor(securityProperties));
        } else if (startElement.getName().equals(Constants.TAG_wsu_Timestamp)) {
            inputProcessorChain.addProcessor(new TimestampInputProcessor(securityProperties));
        } else if (startElement.getName().equals(Constants.TAG_xenc_ReferenceList)) {
            inputProcessorChain.addProcessor(new ReferenceListInputProcessor(securityProperties));
        }
    }

    public class InternalSecurityHeaderProcessor extends AbstractInputProcessor {

        InternalSecurityHeaderProcessor(SecurityProperties securityProperties) {
            super(securityProperties);
            setPhase(Constants.Phase.POSTPROCESSING);
            getBeforeProcessors().add(PipedInputProcessor.class.getName());
        }

        @Override
        public void processSecurityHeaderEvent(XMLEvent xmlEvent, InputProcessorChain inputProcessorChain) throws XMLStreamException, XMLSecurityException {
            xmlEventList.enqueue(xmlEvent);
        }

        @Override
        public void processEvent(XMLEvent xmlEvent, InputProcessorChain inputProcessorChain) throws XMLStreamException, XMLSecurityException {
            //should never be called because we remove this processor before
            inputProcessorChain.processEvent(xmlEvent);
        }
    }
}
