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
package org.swssf.impl.processor.input;

import org.swssf.ext.*;

import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.EndElement;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;
import java.util.ArrayDeque;

/**
 * Processor for the Security-Header XML Structure.
 * This processor instantiates more processors on demand 
 * @author $Author: giger $
 * @version $Revision: 281 $ $Date: 2011-01-04 21:15:27 +0100 (Tue, 04 Jan 2011) $
 */
public class SecurityHeaderInputProcessor extends AbstractInputProcessor {

    private ArrayDeque<XMLEvent> xmlEventList = new ArrayDeque<XMLEvent>();
    private int eventCount = 0;
    private int countOfEventsToResponsibleSecurityHeader = 0;

    public SecurityHeaderInputProcessor(SecurityProperties securityProperties) {
        super(securityProperties);
        setPhase(Constants.Phase.POSTPROCESSING);
    }

    @Override
    public XMLEvent processNextHeaderEvent(InputProcessorChain inputProcessorChain) throws XMLStreamException, XMLSecurityException {
        return null;
    }

    @Override
    public XMLEvent processNextEvent(InputProcessorChain inputProcessorChain) throws XMLStreamException, XMLSecurityException {

        //buffer all events until the end of the security header
        InputProcessorChain subInputProcessorChain = inputProcessorChain.createSubChain(this);
        InternalSecurityHeaderBufferProcessor internalSecurityHeaderBufferProcessor = new InternalSecurityHeaderBufferProcessor(getSecurityProperties());
        subInputProcessorChain.addProcessor(internalSecurityHeaderBufferProcessor);

        XMLEvent xmlEvent;
        do {
            subInputProcessorChain.reset();
            xmlEvent = subInputProcessorChain.processHeaderEvent();

            eventCount++;

            if (xmlEvent.isStartElement()) {
                StartElement startElement = xmlEvent.asStartElement();
                if (subInputProcessorChain.getDocumentContext().getDocumentLevel() == 3
                        && subInputProcessorChain.getDocumentContext().isInSOAPHeader()
                        && startElement.getName().equals(Constants.TAG_wsse_Security)) {

                    subInputProcessorChain.getDocumentContext().setInSecurityHeader(true);
                    //minus one because the first event will be deqeued when finished security header. @see below
                    countOfEventsToResponsibleSecurityHeader = eventCount - 1;

                } else if (subInputProcessorChain.getDocumentContext().getDocumentLevel() == 4
                        && subInputProcessorChain.getDocumentContext().isInSecurityHeader()) {
                    //we are in the security header and the depth is +1, so every child
                    //element should have a responsible processor:
                    engageProcessor(subInputProcessorChain, startElement, getSecurityProperties());
                }
            }

            if (xmlEvent.isEndElement()) {
                EndElement endElement = xmlEvent.asEndElement();
                if (subInputProcessorChain.getDocumentContext().getDocumentLevel() == 2
                        && endElement.getName().equals(Constants.TAG_wsse_Security)) {

                    subInputProcessorChain.getDocumentContext().setInSecurityHeader(false);
                    subInputProcessorChain.removeProcessor(internalSecurityHeaderBufferProcessor);
                    subInputProcessorChain.addProcessor(
                            new InternalSecurityHeaderReplayProcessor(getSecurityProperties(),
                                    countOfEventsToResponsibleSecurityHeader,
                                    //minus one because the first event will be deqeued when finished security header. @see below
                                    eventCount - 1));

                    //since we are replaying the whole envelope strip the path:
                    subInputProcessorChain.getDocumentContext().getPath().clear();
                    //remove this processor from chain now. the next events will go directly to the other processors
                    subInputProcessorChain.removeProcessor(this);

                    countOfEventsToResponsibleSecurityHeader = 0;

                    //return first event now;
                    return xmlEventList.pollLast();
                }
            }

        } while (!(xmlEvent.isStartElement() && xmlEvent.asStartElement().getName().equals(Constants.TAG_soap11_Body)));
        //if we reach this state we didn't find a security header
        throw new XMLSecurityException("No Security");
    }

    //todo move this method. DecryptProcessor should not have a dependency to this processor
    //this must be configurable in a xml file. Create a class that looks up the responsible processor

    public static void engageProcessor(InputProcessorChain inputProcessorChain, StartElement startElement, SecurityProperties securityProperties) {
        if (startElement.getName().equals(Constants.TAG_wsse_BinarySecurityToken)) {
            inputProcessorChain.addProcessor(new BinarySecurityTokenInputProcessor(securityProperties, startElement));
        } else if (startElement.getName().equals(Constants.TAG_xenc_EncryptedKey)) {
            inputProcessorChain.addProcessor(new EncryptedKeyInputProcessor(securityProperties, startElement));
        } else if (startElement.getName().equals(Constants.TAG_dsig_Signature)) {
            inputProcessorChain.addProcessor(new SignatureInputProcessor(securityProperties, startElement));
        } else if (startElement.getName().equals(Constants.TAG_wsu_Timestamp)) {
            inputProcessorChain.addProcessor(new TimestampInputProcessor(securityProperties, startElement));
        } else if (startElement.getName().equals(Constants.TAG_xenc_ReferenceList)) {
            inputProcessorChain.addProcessor(new ReferenceListInputProcessor(securityProperties, startElement));
        }
    }

    /**
     * Temporary Processor to buffer all events until the end of the security header
     */
    public class InternalSecurityHeaderBufferProcessor extends AbstractInputProcessor {

        InternalSecurityHeaderBufferProcessor(SecurityProperties securityProperties) {
            super(securityProperties);
            setPhase(Constants.Phase.POSTPROCESSING);
            getBeforeProcessors().add(SecurityHeaderInputProcessor.class.getName());
        }

        @Override
        public XMLEvent processNextHeaderEvent(InputProcessorChain inputProcessorChain) throws XMLStreamException, XMLSecurityException {
            XMLEvent xmlEvent = inputProcessorChain.processHeaderEvent();
            xmlEventList.push(xmlEvent);
            return xmlEvent;
        }

        @Override
        public XMLEvent processNextEvent(InputProcessorChain inputProcessorChain) throws XMLStreamException, XMLSecurityException {
            //should never be called because we remove this processor before
            return null;
        }
    }

    /**
     * Temporary processor to replay the buffered events
     */
    public class InternalSecurityHeaderReplayProcessor extends AbstractInputProcessor {

        private int countOfEventsToResponsibleSecurityHeader = 0;
        private int countOfEventsUntilEndOfResponsibleSecurityHeader = 0;
        private int eventCount = 0;

        public InternalSecurityHeaderReplayProcessor(SecurityProperties securityProperties, int countOfEventsToResponsibleSecurityHeader, int countOfEventsUntilEndOfResponsibleSecurityHeader) {
            super(securityProperties);
            setPhase(Constants.Phase.PREPROCESSING);
            getBeforeProcessors().add(SecurityHeaderInputProcessor.class.getName());
            getAfterProcessors().add(XMLEventReaderInputProcessor.class.getName());
            this.countOfEventsToResponsibleSecurityHeader = countOfEventsToResponsibleSecurityHeader;
            this.countOfEventsUntilEndOfResponsibleSecurityHeader = countOfEventsUntilEndOfResponsibleSecurityHeader;
        }

        @Override
        public XMLEvent processNextHeaderEvent(InputProcessorChain inputProcessorChain) throws XMLStreamException, XMLSecurityException {
            return null;
        }

        @Override
        public XMLEvent processNextEvent(InputProcessorChain inputProcessorChain) throws XMLStreamException, XMLSecurityException {

            if (!xmlEventList.isEmpty()) {
                eventCount++;

                if (eventCount == countOfEventsToResponsibleSecurityHeader) {
                    inputProcessorChain.getDocumentContext().setInSecurityHeader(true);
                }
                if (eventCount == countOfEventsUntilEndOfResponsibleSecurityHeader) {
                    inputProcessorChain.getDocumentContext().setInSecurityHeader(false);
                }

                XMLEvent xmlEvent = xmlEventList.pollLast();
                if (xmlEvent.isStartElement()) {
                    inputProcessorChain.getDocumentContext().addPathElement(xmlEvent.asStartElement().getName());
                } else if (xmlEvent.isEndElement()) {
                    inputProcessorChain.getDocumentContext().removePathElement();
                }
                return xmlEvent;

            } else {
                inputProcessorChain.removeProcessor(this);
                return inputProcessorChain.processEvent();
            }
        }
    }
}
