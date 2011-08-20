/**
 * Copyright 2010, 2011 Marc Giger
 *
 * This file is part of the streaming-webservice-security-framework (swssf).
 *
 * The streaming-webservice-security-framework is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * The streaming-webservice-security-framework is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with the streaming-webservice-security-framework.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.swssf.impl.processor.input;

import org.swssf.ext.*;

import javax.xml.stream.XMLEventReader;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.XMLEvent;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.List;

/**
 * The XMLEventReaderInputProcessor reads requested XMLEvents from the original XMLEventReader
 * and returns them to the requestor
 *
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class XMLEventReaderInputProcessor extends AbstractInputProcessor {

    private XMLEventReader xmlEventReader;
    private Deque<List<ComparableNamespace>> nsStack = new ArrayDeque<List<ComparableNamespace>>(10);
    private Deque<List<ComparableAttribute>> attrStack = new ArrayDeque<List<ComparableAttribute>>(10);

    public XMLEventReaderInputProcessor(SecurityProperties securityProperties, XMLEventReader xmlEventReader) {
        super(securityProperties);
        setPhase(Constants.Phase.PREPROCESSING);
        this.xmlEventReader = xmlEventReader;
    }

    @Override
    public XMLEvent processNextHeaderEvent(InputProcessorChain inputProcessorChain) throws XMLStreamException, WSSecurityException {
        return processNextEventInternal(inputProcessorChain);
    }

    @Override
    public XMLEvent processNextEvent(InputProcessorChain inputProcessorChain) throws XMLStreamException, WSSecurityException {
        return processNextEventInternal(inputProcessorChain);
    }

    private XMLEvent processNextEventInternal(InputProcessorChain inputProcessorChain) throws XMLStreamException {
        XMLEvent xmlEvent = Utils.createXMLEventNS(xmlEventReader.nextEvent(), nsStack, attrStack);
        if (xmlEvent.isStartElement()) {
            inputProcessorChain.getDocumentContext().addPathElement(xmlEvent.asStartElement().getName());
        } else if (xmlEvent.isEndElement()) {
            inputProcessorChain.getDocumentContext().removePathElement();
        }
        return xmlEvent;
    }

    @Override
    public void doFinal(InputProcessorChain inputProcessorChain) throws XMLStreamException, WSSecurityException {
        //nothing to-do. Also don't call super.doFinal() we are the last processor
    }
}
