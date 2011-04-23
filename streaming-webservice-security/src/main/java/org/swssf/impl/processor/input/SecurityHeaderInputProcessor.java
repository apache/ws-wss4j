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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.swssf.config.SecurityHeaderHandlerMapper;
import org.swssf.ext.*;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.EndElement;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Deque;

/**
 * Processor for the Security-Header XML Structure.
 * This processor instantiates more processors on demand
 *
 * @author $Author: giger $
 * @version $Revision: 281 $ $Date: 2011-01-04 21:15:27 +0100 (Tue, 04 Jan 2011) $
 */
public class SecurityHeaderInputProcessor extends AbstractInputProcessor {

    protected static final transient Log logger = LogFactory.getLog(SecurityHeaderInputProcessor.class);

    private ArrayDeque<XMLEvent> xmlEventList = new ArrayDeque<XMLEvent>();
    private int eventCount = 0;
    private int countOfEventsToResponsibleSecurityHeader = 0;
    private int startIndexForProcessor = 0;

    public SecurityHeaderInputProcessor(SecurityProperties securityProperties) {
        super(securityProperties);
        setPhase(Constants.Phase.POSTPROCESSING);
    }

    @Override
    public XMLEvent processNextHeaderEvent(InputProcessorChain inputProcessorChain) throws XMLStreamException, WSSecurityException {
        return null;
    }

    @Override
    public XMLEvent processNextEvent(InputProcessorChain inputProcessorChain) throws XMLStreamException, WSSecurityException {

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

                if (subInputProcessorChain.getDocumentContext().getDocumentLevel() == 1) {
                    if (subInputProcessorChain.getDocumentContext().getSOAPMessageVersionNamespace() == null) {
                        throw new WSSecurityException(WSSecurityException.FAILURE, "notASOAPMessage");
                    }
                } else if (subInputProcessorChain.getDocumentContext().getDocumentLevel() == 3
                        && subInputProcessorChain.getDocumentContext().isInSOAPHeader()
                        && startElement.getName().equals(Constants.TAG_wsse_Security)) {

                    subInputProcessorChain.getDocumentContext().setInSecurityHeader(true);
                    //minus one because the first event will be deqeued when finished security header. @see below
                    countOfEventsToResponsibleSecurityHeader = eventCount - 1;

                } else if (subInputProcessorChain.getDocumentContext().getDocumentLevel() == 4
                        && subInputProcessorChain.getDocumentContext().isInSecurityHeader()) {
                    startIndexForProcessor = eventCount - 1;
                }
            } else if (xmlEvent.isEndElement()) {
                EndElement endElement = xmlEvent.asEndElement();
                if (subInputProcessorChain.getDocumentContext().getDocumentLevel() == 2
                        && endElement.getName().equals(Constants.TAG_wsse_Security)) {

                    //subInputProcessorChain.getDocumentContext().setInSecurityHeader(false);
                    subInputProcessorChain.removeProcessor(internalSecurityHeaderBufferProcessor);
                    subInputProcessorChain.addProcessor(
                            new InternalSecurityHeaderReplayProcessor(getSecurityProperties(),
                                    countOfEventsToResponsibleSecurityHeader,
                                    //minus one because the first event will be deqeued when finished security header. @see below
                                    eventCount - 1));

                    //remove this processor from chain now. the next events will go directly to the other processors
                    subInputProcessorChain.removeProcessor(this);
                    //since we clone the inputProcessor list we have to add the processors from
                    //the subChain to the main chain.
                    inputProcessorChain.getProcessors().clear();
                    inputProcessorChain.getProcessors().addAll(subInputProcessorChain.getProcessors());

                    countOfEventsToResponsibleSecurityHeader = 0;

                    //return first event now;
                    return xmlEventList.pollLast();
                } else if (subInputProcessorChain.getDocumentContext().getDocumentLevel() == 3
                        && subInputProcessorChain.getDocumentContext().isInSecurityHeader()) {
                    //we are in the security header and the depth is +1, so every child
                    //element should have a responsible processor:
                    engageSecurityHeaderHandler(subInputProcessorChain, getSecurityProperties(), xmlEventList, startIndexForProcessor, endElement.getName());
                }
            }

        } while (!(xmlEvent.isStartElement()
                && xmlEvent.asStartElement().getName().getLocalPart().equals(Constants.TAG_soap_Body_LocalName)
                && xmlEvent.asStartElement().getName().getNamespaceURI().equals(subInputProcessorChain.getDocumentContext().getSOAPMessageVersionNamespace())
        ));
        //if we reach this state we didn't find a security header
        throw new WSSecurityException(WSSecurityException.FAILURE, "missingSecurityHeader");
    }

    private static void engageSecurityHeaderHandler(InputProcessorChain inputProcessorChain,
                                                    SecurityProperties securityProperties,
                                                    Deque eventQueue,
                                                    Integer index,
                                                    QName elementName)
            throws WSSecurityException, XMLStreamException {

        Class clazz = SecurityHeaderHandlerMapper.getSecurityHeaderHandler(elementName);
        if (clazz == null) {
            return;
        }
        Constructor[] constructors = clazz.getConstructors();
        Comparator<Constructor> comparator = new Comparator<Constructor>() {
            public int compare(Constructor o1, Constructor o2) {
                if (o1.getParameterTypes().length == o2.getParameterTypes().length) {
                    return 0;
                } else if (o1.getParameterTypes().length > o2.getParameterTypes().length) {
                    return -1;
                } else {
                    return 1;
                }
            }
        };

        Arrays.sort(constructors, comparator);

        for (int i = 0; i < constructors.length; i++) {
            Constructor constructor = constructors[i];
            Class[] parameterTypes = constructor.getParameterTypes();

            boolean ok = true;
            Object[] parameterObjects = new Object[parameterTypes.length];
            for (int j = 0; j < parameterTypes.length; j++) {
                Class parameterType = parameterTypes[j];
                if (parameterType.isAssignableFrom(inputProcessorChain.getClass())) {
                    parameterObjects[j] = inputProcessorChain;
                } else if (parameterType.isAssignableFrom(securityProperties.getClass())) {
                    parameterObjects[j] = securityProperties;
                } else if (parameterType.isAssignableFrom(eventQueue.getClass())) {
                    parameterObjects[j] = eventQueue;
                } else if (parameterType.isAssignableFrom(index.getClass())) {
                    parameterObjects[j] = index;
                } else if (parameterType.isAssignableFrom(elementName.getClass())) {
                    parameterObjects[j] = elementName;
                } else {
                    ok = false;
                    break;
                }
            }
            if (ok) {
                try {
                    constructor.newInstance(parameterObjects);
                } catch (InstantiationException e) {
                    logger.warn(e);
                } catch (IllegalAccessException e) {
                    logger.warn(e);
                } catch (InvocationTargetException e) {
                    Throwable cause = e.getCause();
                    if (cause instanceof WSSecurityException) {
                        throw (WSSecurityException) cause;
                    } else if (cause instanceof XMLStreamException) {
                        throw (XMLStreamException) cause;
                    } else {
                        throw new RuntimeException(e.getCause());
                    }
                }
                return;
            }
            logger.warn("No matching handler found for " + elementName);
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
        public XMLEvent processNextHeaderEvent(InputProcessorChain inputProcessorChain) throws XMLStreamException, WSSecurityException {
            XMLEvent xmlEvent = inputProcessorChain.processHeaderEvent();
            xmlEventList.push(xmlEvent);
            return xmlEvent;
        }

        @Override
        public XMLEvent processNextEvent(InputProcessorChain inputProcessorChain) throws XMLStreamException, WSSecurityException {
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
        public XMLEvent processNextHeaderEvent(InputProcessorChain inputProcessorChain) throws XMLStreamException, WSSecurityException {
            return null;
        }

        @Override
        public XMLEvent processNextEvent(InputProcessorChain inputProcessorChain) throws XMLStreamException, WSSecurityException {

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
