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

import javax.xml.stream.events.XMLEvent;

/**
 * Parseable interface to parse and validate xml
 *
 * @author $Author$
 * @version $Revision$ $Date$
 */
public interface Parseable {

    /**
     * @param xmlEvent The XMLEvent to parse
     * @return true when current Element is finished
     * @throws ParseException in the case of an unexpected element
     */
    public boolean parseXMLEvent(XMLEvent xmlEvent) throws ParseException;

    /**
     * Validates the XML-Object structure
     *
     * @throws ParseException thrown when the the object-structure is invalid
     */
    public void validate() throws ParseException;
}
