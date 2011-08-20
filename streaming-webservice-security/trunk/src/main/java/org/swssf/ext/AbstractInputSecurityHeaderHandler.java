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
