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
package org.swssf.ext;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;
import java.util.Deque;
import java.util.Iterator;

/**
 * Abstract class for SecurityHeaderHandlers with parse logic for the xml structures
 *
 * @author $Author$
 * @version $Revision$ $Date$
 */
public abstract class AbstractInputSecurityHeaderHandler {

    protected final transient Log logger = LogFactory.getLog(this.getClass());

    protected abstract Parseable getParseable(StartElement startElement);

    protected Parseable parseStructure(Deque<XMLEvent> eventDeque, int index) throws WSSecurityException {
        Iterator<XMLEvent> iterator = eventDeque.descendingIterator();
        //skip to <XY> Element
        int i = 0;
        while (i < index) {
            iterator.next();
            i++;
        }

        if (!iterator.hasNext()) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY, "unexpectedEndOfXML");
        }
        XMLEvent xmlEvent = iterator.next();
        if (!xmlEvent.isStartElement()) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY, "notAStartElement");
        }
        Parseable parseable = getParseable(xmlEvent.asStartElement());

        try {
            while (iterator.hasNext()) {
                xmlEvent = iterator.next();
                parseable.parseXMLEvent(xmlEvent);
            }
            parseable.validate();
        } catch (ParseException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY, e);
        }
        return parseable;
    }
}
