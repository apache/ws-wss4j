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
