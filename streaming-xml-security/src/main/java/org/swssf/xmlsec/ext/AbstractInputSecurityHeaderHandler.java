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
package org.swssf.xmlsec.ext;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.swssf.xmlsec.impl.XMLSecurityEventReader;

import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import javax.xml.namespace.QName;
import javax.xml.stream.events.XMLEvent;
import java.util.ArrayList;
import java.util.Deque;
import java.util.Iterator;
import java.util.List;

/**
 * Abstract class for SecurityHeaderHandlers with parse logic for the xml structures
 *
 * @author $Author$
 * @version $Revision$ $Date$
 */
public abstract class AbstractInputSecurityHeaderHandler implements XMLSecurityHeaderHandler {

    protected final transient Log logger = LogFactory.getLog(this.getClass());

    protected <T> T parseStructure(Deque<XMLEvent> eventDeque, int index) throws XMLSecurityException {
        try {
            Unmarshaller unmarshaller = XMLSecurityConstants.getJaxbContext().createUnmarshaller();
            return (T) unmarshaller.unmarshal(new XMLSecurityEventReader(eventDeque, index));

        } catch (JAXBException e) {
            throw new XMLSecurityException(XMLSecurityException.ErrorCode.INVALID_SECURITY, e);
        }
    }

    protected List<QName> getElementPath(DocumentContext documentContext, Deque<XMLEvent> eventDeque) throws XMLSecurityException {
        List<QName> elementPath = new ArrayList<QName>();
        elementPath.addAll(documentContext.getPath());
        XMLEvent xmlEvent = eventDeque.peek();
        if (xmlEvent.isStartElement()) {
            elementPath.add(xmlEvent.asStartElement().getName());
        } else if (xmlEvent.isEndElement()) {
            elementPath.add(xmlEvent.asEndElement().getName());
        } else {
            throw new XMLSecurityException(XMLSecurityException.ErrorCode.INVALID_SECURITY);
        }
        return elementPath;
    }

    protected XMLEvent getResponsibleStartXMLEvent(Deque<XMLEvent> eventDeque, int index) {
        Iterator<XMLEvent> xmlEventIterator = eventDeque.descendingIterator();
        int curIdx = 0;
        while (curIdx++ < index) {
            xmlEventIterator.next();
        }
        return xmlEventIterator.next();
    }
}
