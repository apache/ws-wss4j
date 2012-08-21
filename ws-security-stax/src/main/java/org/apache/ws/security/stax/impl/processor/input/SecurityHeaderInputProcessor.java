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
package org.apache.ws.security.stax.impl.processor.input;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.common.ext.WSSecurityException;
import org.apache.ws.security.stax.ext.WSSConstants;
import org.apache.ws.security.stax.ext.WSSSecurityProperties;
import org.apache.ws.security.stax.ext.WSSUtils;
import org.apache.xml.security.stax.config.SecurityHeaderHandlerMapper;
import org.apache.xml.security.stax.ext.*;
import org.apache.xml.security.stax.ext.stax.XMLSecEndElement;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;
import org.apache.xml.security.stax.ext.stax.XMLSecStartElement;
import org.apache.xml.security.stax.impl.processor.input.XMLEventReaderInputProcessor;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
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

    private final ArrayDeque<XMLSecEvent> xmlSecEventList = new ArrayDeque<XMLSecEvent>();
    private int eventCount = 0;
    private int startIndexForProcessor = 0;

    public SecurityHeaderInputProcessor(WSSSecurityProperties securityProperties) {
        super(securityProperties);
        setPhase(WSSConstants.Phase.POSTPROCESSING);
    }

    @Override
    public XMLSecEvent processNextHeaderEvent(InputProcessorChain inputProcessorChain)
            throws XMLStreamException, XMLSecurityException {
        return null;
    }

    @Override
    public XMLSecEvent processNextEvent(InputProcessorChain inputProcessorChain)
            throws XMLStreamException, XMLSecurityException {

        //buffer all events until the end of the security header
        final InputProcessorChain subInputProcessorChain = inputProcessorChain.createSubChain(this);
        final InternalSecurityHeaderBufferProcessor internalSecurityHeaderBufferProcessor
                = new InternalSecurityHeaderBufferProcessor(getSecurityProperties());
        subInputProcessorChain.addProcessor(internalSecurityHeaderBufferProcessor);

        boolean responsibleSecurityHeaderFound = false;

        XMLSecEvent xmlSecEvent;
        do {
            subInputProcessorChain.reset();
            xmlSecEvent = subInputProcessorChain.processHeaderEvent();
            eventCount++;

            switch (xmlSecEvent.getEventType()) {
                case XMLStreamConstants.START_ELEMENT:
                    XMLSecStartElement xmlSecStartElement = xmlSecEvent.asStartElement();
                    int documentLevel = xmlSecStartElement.getDocumentLevel();

                    if (documentLevel == 1) {
                        if (WSSUtils.getSOAPMessageVersionNamespace(xmlSecStartElement) == null) {
                            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "notASOAPMessage");
                        }
                    } else if (documentLevel == 3
                            && xmlSecStartElement.getName().equals(WSSConstants.TAG_wsse_Security)
                            && WSSUtils.isInSOAPHeader(xmlSecStartElement)) {

                        if (!WSSUtils.isResponsibleActorOrRole(xmlSecStartElement,
                                ((WSSSecurityProperties) getSecurityProperties()).getActor())) {
                            continue;
                        }
                        responsibleSecurityHeaderFound = true;

                    } else if (documentLevel == 4 && responsibleSecurityHeaderFound
                            && WSSUtils.isInSecurityHeader(xmlSecStartElement,
                            ((WSSSecurityProperties) getSecurityProperties()).getActor())) {
                        startIndexForProcessor = eventCount - 1;
                    }
                    break;
                case XMLStreamConstants.END_ELEMENT:
                    XMLSecEndElement xmlSecEndElement = xmlSecEvent.asEndElement();
                    documentLevel = xmlSecEndElement.getDocumentLevel();
                    if (documentLevel == 3 && responsibleSecurityHeaderFound
                            && xmlSecEndElement.getName().equals(WSSConstants.TAG_wsse_Security)) {

                        //subInputProcessorChain.getDocumentContext().setInSecurityHeader(false);
                        subInputProcessorChain.removeProcessor(internalSecurityHeaderBufferProcessor);
                        subInputProcessorChain.addProcessor(
                                new InternalSecurityHeaderReplayProcessor(getSecurityProperties()));

                        //remove this processor from chain now. the next events will go directly to the other processors
                        subInputProcessorChain.removeProcessor(this);
                        //since we cloned the inputProcessor list we have to add the processors from
                        //the subChain to the main chain.
                        inputProcessorChain.getProcessors().clear();
                        inputProcessorChain.getProcessors().addAll(subInputProcessorChain.getProcessors());

                        //return first event now;
                        return xmlSecEventList.pollLast();
                    } else if (documentLevel == 4 && responsibleSecurityHeaderFound
                            && WSSUtils.isInSecurityHeader(xmlSecEndElement,
                            ((WSSSecurityProperties) getSecurityProperties()).getActor())) {
                        //we are in the security header and the depth is +1, so every child
                        //element should have a responsible handler:
                        engageSecurityHeaderHandler(subInputProcessorChain, getSecurityProperties(),
                                xmlSecEventList, startIndexForProcessor, xmlSecEndElement.getName());
                    }
                    break;
            }

        } while (!(xmlSecEvent.getEventType() == XMLStreamConstants.START_ELEMENT
                && xmlSecEvent.asStartElement().getName().getLocalPart().equals(WSSConstants.TAG_soap_Body_LocalName)
                && xmlSecEvent.asStartElement().getName().getNamespaceURI().equals(
                WSSUtils.getSOAPMessageVersionNamespace(xmlSecEvent.asStartElement()))
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

        Class<XMLSecurityHeaderHandler> clazz = 
            (Class<XMLSecurityHeaderHandler>)SecurityHeaderHandlerMapper.getSecurityHeaderHandler(elementName);
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
        public XMLSecEvent processNextHeaderEvent(InputProcessorChain inputProcessorChain)
                throws XMLStreamException, XMLSecurityException {
            XMLSecEvent xmlSecEvent = inputProcessorChain.processHeaderEvent();
            xmlSecEventList.push(xmlSecEvent);
            return xmlSecEvent;
        }

        @Override
        public XMLSecEvent processNextEvent(InputProcessorChain inputProcessorChain)
                throws XMLStreamException, XMLSecurityException {
            //should never be called because we remove this processor before
            return null;
        }
    }

    /**
     * Temporary processor to replay the buffered events
     */
    public class InternalSecurityHeaderReplayProcessor extends AbstractInputProcessor {

        public InternalSecurityHeaderReplayProcessor(XMLSecurityProperties securityProperties) {
            super(securityProperties);
            setPhase(WSSConstants.Phase.PREPROCESSING);
            addBeforeProcessor(SecurityHeaderInputProcessor.class.getName());
            addAfterProcessor(XMLEventReaderInputProcessor.class.getName());
        }

        @Override
        public XMLSecEvent processNextHeaderEvent(InputProcessorChain inputProcessorChain)
                throws XMLStreamException, XMLSecurityException {
            return null;
        }

        @Override
        public XMLSecEvent processNextEvent(InputProcessorChain inputProcessorChain)
                throws XMLStreamException, XMLSecurityException {

            if (!xmlSecEventList.isEmpty()) {
                return xmlSecEventList.pollLast();
            } else {
                inputProcessorChain.removeProcessor(this);
                return inputProcessorChain.processEvent();
            }
        }
    }
}
