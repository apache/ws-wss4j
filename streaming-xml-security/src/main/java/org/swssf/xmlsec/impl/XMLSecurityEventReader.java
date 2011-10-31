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

package org.swssf.xmlsec.impl;

import javax.xml.stream.XMLEventReader;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.XMLEvent;
import java.util.Deque;
import java.util.Iterator;
import java.util.NoSuchElementException;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class XMLSecurityEventReader implements XMLEventReader {

    private Iterator<XMLEvent> xmlEventIterator;
    private XMLEvent currentXMLEvent;
    private XMLEvent nextXMLEvent;

    public XMLSecurityEventReader(Deque<XMLEvent> xmlEvents, int fromIndex) {
        this.xmlEventIterator = xmlEvents.descendingIterator();
        int curIdx = 0;
        while (curIdx++ < fromIndex) {
            this.xmlEventIterator.next();
        }
    }

    @Override
    public XMLEvent nextEvent() throws XMLStreamException {
        if (this.nextXMLEvent != null) {
            this.currentXMLEvent = this.nextXMLEvent;
            this.nextXMLEvent = null;
            return this.currentXMLEvent;
        }
        try {
            this.currentXMLEvent = xmlEventIterator.next();
        } catch (NoSuchElementException e) {
            throw new XMLStreamException(e);
        }
        return this.currentXMLEvent;
    }

    @Override
    public boolean hasNext() {
        if (this.nextXMLEvent != null) {
            return true;
        }
        return xmlEventIterator.hasNext();
    }

    @Override
    public XMLEvent peek() throws XMLStreamException {
        if (this.nextXMLEvent != null) {
            return this.nextXMLEvent;
        }
        try {
            return this.nextXMLEvent = xmlEventIterator.next();
        } catch (NoSuchElementException e) {
            return null;
        }
    }

    @Override
    public String getElementText() throws XMLStreamException {
        //ATM not needed and therefore not implemented
        throw new XMLStreamException(new UnsupportedOperationException());
    }

    @Override
    public XMLEvent nextTag() throws XMLStreamException {
        //ATM not needed and therefore not implemented
        throw new XMLStreamException(new UnsupportedOperationException());
    }

    @Override
    public Object getProperty(String name) throws IllegalArgumentException {
        //ATM not needed and therefore not implemented
        throw new IllegalArgumentException(new UnsupportedOperationException());
    }

    @Override
    public void close() throws XMLStreamException {
        //nop
    }

    @Override
    public Object next() {
        try {
            return nextEvent();
        } catch (XMLStreamException e) {
            throw new NoSuchElementException(e.getMessage());
        }
    }

    @Override
    public void remove() {
        throw new UnsupportedOperationException();
    }
}
