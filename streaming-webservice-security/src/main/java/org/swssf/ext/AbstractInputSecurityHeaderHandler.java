/*
 * Copyright 1996-2011 itServe AG. All rights reserved.
 *
 * This software is the proprietary information of itServe AG
 * Bern Switzerland. Use is subject to license terms.
 *
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
 * @author $Author: $
 * @version $Revision: $ $Date: $
 */
public abstract class AbstractInputSecurityHeaderHandler {

    protected final transient Log logger = LogFactory.getLog(this.getClass());

    protected abstract Parseable getParseable(StartElement startElement);

    protected Parseable parseStructure(Deque<XMLEvent> eventDeque, int index) throws WSSecurityException {
        Iterator<XMLEvent> iterator = eventDeque.descendingIterator();
        //skip to <XY> Element
        int i = 0;
        while (i < index){
            iterator.next();
            i++;
        }

        if (!iterator.hasNext()) {
            throw new WSSecurityException("No Element");
        }
        XMLEvent xmlEvent = iterator.next();
        if (!xmlEvent.isStartElement()) {
            throw new WSSecurityException("No StartElement");
        }
        Parseable parseable = getParseable(xmlEvent.asStartElement());

        try {
            while (iterator.hasNext()) {
                xmlEvent = iterator.next();
                parseable.parseXMLEvent(xmlEvent);
            }
            parseable.validate();
        } catch (ParseException e) {
            throw new WSSecurityException(e);
        }
        return parseable;
    }
}
