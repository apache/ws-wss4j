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

import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.XMLEvent;
import java.util.Set;

/**
 * This is the Interface which every OutputProcessor must implement.
 *
 * @author $Author$
 * @version $Revision$ $Date$
 */
public interface OutputProcessor {

    /**
     * This OutputProcessor will be added before the processors in this set
     *
     * @return The set with the named OutputProcessor
     */
    Set<Object> getBeforeProcessors();

    /**
     * This OutputProcessor will be added after the processors in this set
     *
     * @return The set with the named OutputProcessor
     */
    Set<Object> getAfterProcessors();

    /**
     * The Phase in which this OutputProcessor should be applied
     *
     * @return The Phase
     */
    Constants.Phase getPhase();

    /**
     * Will be called from the framework for every XMLEvent
     *
     * @param xmlEvent             The next XMLEvent to process
     * @param outputProcessorChain
     * @throws XMLStreamException  thrown when a streaming error occurs
     * @throws WSSecurityException thrown when a Security failure occurs
     */
    void processNextEvent(XMLEvent xmlEvent, OutputProcessorChain outputProcessorChain) throws XMLStreamException, WSSecurityException;

    /**
     * Will be called when the whole document is processed.
     *
     * @param outputProcessorChain
     * @throws XMLStreamException  thrown when a streaming error occurs
     * @throws WSSecurityException thrown when a Security failure occurs
     */
    void doFinal(OutputProcessorChain outputProcessorChain) throws XMLStreamException, WSSecurityException;
}
