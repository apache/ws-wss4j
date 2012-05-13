/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.swssf.wss.impl.processor.input;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.swssf.wss.ext.*;
import org.swssf.xmlsec.config.SecurityHeaderHandlerMapper;
import org.swssf.xmlsec.ext.*;
import org.swssf.xmlsec.impl.processor.input.XMLEventReaderInputProcessor;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.EndElement;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;
import java.util.ArrayDeque;
import java.util.Deque;

/**
 * Processor for the Security-Header XML Structure.
 * This processor instantiates more processors on demand
 *
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class SecurityHeaderInputProcessor extends AbstractInputProcessor {

    protected static final transient Log logger = LogFactory.getLog(SecurityHeaderInputProcessor.class);

    private ArrayDeque<XMLEvent> xmlEventList = new ArrayDeque<XMLEvent>();
    private int eventCount = 0;
    private int countOfEventsToResponsibleSecurityHeader = 0;
    private int startIndexForProcessor = 0;

    public SecurityHeaderInputProcessor(WSSSecurityProperties securityProperties) {
        super(securityProperties);
        setPhase(WSSConstants.Phase.POSTPROCESSING);
    }

    @Override
    public XMLEvent processNextHeaderEvent(InputProcessorChain inputProcessorChain) throws XMLStreamException, XMLSecurityException {
        return null;
    }

    @Override
    public XMLEvent processNextEvent(InputProcessorChain inputProcessorChain) throws XMLStreamException, XMLSecurityException {

        //buffer all events until the end of the security header
        final InputProcessorChain subInputProcessorChain = inputProcessorChain.createSubChain(this);
        final InternalSecurityHeaderBufferProcessor internalSecurityHeaderBufferProcessor
                = new InternalSecurityHeaderBufferProcessor(getSecurityProperties());
        subInputProcessorChain.addProcessor(internalSecurityHeaderBufferProcessor);
        final WSSDocumentContext documentContext = (WSSDocumentContext) subInputProcessorChain.getDocumentContext();

        boolean responsibleSecurityHeaderFound = false;

        XMLEvent xmlEvent;
        do {
            subInputProcessorChain.reset();
            xmlEvent = subInputProcessorChain.processHeaderEvent();
            eventCount++;
            final int documentLevel = documentContext.getDocumentLevel();

            if (xmlEvent.isStartElement()) {
                StartElement startElement = xmlEvent.asStartElement();

                if (documentLevel == 1) {
                    if (documentContext.getSOAPMessageVersionNamespace() == null) {
                        throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "notASOAPMessage");
                    }
                } else if (documentLevel == 3
                        && documentContext.isInSOAPHeader()
                        && startElement.getName().equals(WSSConstants.TAG_wsse_Security)) {

                    if (!WSSUtils.isResponsibleActorOrRole(startElement,
                            documentContext.getSOAPMessageVersionNamespace(),
                            ((WSSSecurityProperties) getSecurityProperties()).getActor())) {
                        continue;
                    }

                    responsibleSecurityHeaderFound = true;
                    documentContext.setInSecurityHeader(true);
                    //minus one because the first event will be deqeued when finished security header. @see below
                    countOfEventsToResponsibleSecurityHeader = eventCount - 1;

                } else if (documentLevel == 4
                        && documentContext.isInSecurityHeader()) {
                    startIndexForProcessor = eventCount - 1;
                }
            } else if (xmlEvent.isEndElement()) {
                EndElement endElement = xmlEvent.asEndElement();
                if (responsibleSecurityHeaderFound && documentLevel == 2
                        && endElement.getName().equals(WSSConstants.TAG_wsse_Security)) {

                    //subInputProcessorChain.getDocumentContext().setInSecurityHeader(false);
                    subInputProcessorChain.removeProcessor(internalSecurityHeaderBufferProcessor);
                    subInputProcessorChain.addProcessor(
                            new InternalSecurityHeaderReplayProcessor(getSecurityProperties(),
                                    countOfEventsToResponsibleSecurityHeader,
                                    //minus one because the first event will be deqeued when finished security header. @see below
                                    eventCount - 1));

                    //remove this processor from chain now. the next events will go directly to the other processors
                    subInputProcessorChain.removeProcessor(this);
                    //since we cloned the inputProcessor list we have to add the processors from
                    //the subChain to the main chain.
                    inputProcessorChain.getProcessors().clear();
                    inputProcessorChain.getProcessors().addAll(subInputProcessorChain.getProcessors());

                    countOfEventsToResponsibleSecurityHeader = 0;

                    //return first event now;
                    return xmlEventList.pollLast();
                } else if (documentLevel == 3
                        && documentContext.isInSecurityHeader()) {
                    //we are in the security header and the depth is +1, so every child
                    //element should have a responsible handler:
                    engageSecurityHeaderHandler(subInputProcessorChain, getSecurityProperties(),
                            xmlEventList, startIndexForProcessor, endElement.getName());
                }
            }

        } while (!(xmlEvent.isStartElement()
                && xmlEvent.asStartElement().getName().getLocalPart().equals(WSSConstants.TAG_soap_Body_LocalName)
                && xmlEvent.asStartElement().getName().getNamespaceURI().equals(
                documentContext.getSOAPMessageVersionNamespace())
        ));
        //if we reach this state we didn't find a security header
        throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "missingSecurityHeader");
    }

    @SuppressWarnings("unchecked")
    private void engageSecurityHeaderHandler(InputProcessorChain inputProcessorChain,
                                             XMLSecurityProperties securityProperties,
                                             Deque eventQueue,
                                             Integer index,
                                             QName elementName)
            throws WSSecurityException, XMLStreamException {

        Class<XMLSecurityHeaderHandler> clazz = SecurityHeaderHandlerMapper.getSecurityHeaderHandler(elementName);
        if (clazz == null) {
            logger.warn("No matching handler found for " + elementName);
            return;
        }
        try {
            XMLSecurityHeaderHandler xmlSecurityHeaderHandler = clazz.newInstance();
            xmlSecurityHeaderHandler.handle(inputProcessorChain, securityProperties, eventQueue, index);
        } catch (InstantiationException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, e);
        } catch (IllegalAccessException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, e);
        } catch (XMLSecurityException e) {
            throw new WSSecurityException(e.getMessage(), e.getCause());
        }
    }

    /**
     * Temporary Processor to buffer all events until the end of the security header
     */
    public class InternalSecurityHeaderBufferProcessor extends AbstractInputProcessor {

        InternalSecurityHeaderBufferProcessor(XMLSecurityProperties securityProperties) {
            super(securityProperties);
            setPhase(WSSConstants.Phase.POSTPROCESSING);
            addBeforeProcessor(SecurityHeaderInputProcessor.class.getName());
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

        public InternalSecurityHeaderReplayProcessor(XMLSecurityProperties securityProperties, int countOfEventsToResponsibleSecurityHeader, int countOfEventsUntilEndOfResponsibleSecurityHeader) {
            super(securityProperties);
            setPhase(WSSConstants.Phase.PREPROCESSING);
            addBeforeProcessor(SecurityHeaderInputProcessor.class.getName());
            addAfterProcessor(XMLEventReaderInputProcessor.class.getName());
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

                final WSSDocumentContext documentContext = (WSSDocumentContext) inputProcessorChain.getDocumentContext();
                if (eventCount == countOfEventsToResponsibleSecurityHeader) {
                    documentContext.setInSecurityHeader(true);
                } else if (eventCount == countOfEventsUntilEndOfResponsibleSecurityHeader) {
                    documentContext.setInSecurityHeader(false);
                }

                XMLEvent xmlEvent = xmlEventList.pollLast();
                if (xmlEvent.isStartElement()) {
                    documentContext.addPathElement(xmlEvent.asStartElement().getName());
                } else if (xmlEvent.isEndElement()) {
                    documentContext.removePathElement();
                }
                return xmlEvent;

            } else {
                inputProcessorChain.removeProcessor(this);
                return inputProcessorChain.processEvent();
            }
        }
    }
}
