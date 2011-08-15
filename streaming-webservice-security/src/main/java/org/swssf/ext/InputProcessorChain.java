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
import java.util.List;

/**
 * The InputProcessorChain manages the InputProcessors and controls the XMLEvent flow
 *
 * @author $Author$
 * @version $Revision$ $Date$
 */
public interface InputProcessorChain extends ProcessorChain {

    /**
     * Adds an InputProcessor to the chain. The place where it
     * will be applied can be controlled through the Phase,
     * getBeforeProcessors and getAfterProcessors. @see Interface InputProcessor
     *
     * @param inputProcessor The InputProcessor which should be placed in the chain
     */
    public void addProcessor(InputProcessor inputProcessor);

    /**
     * Removes the specified InputProcessor from this chain.
     *
     * @param inputProcessor to remove
     */
    public void removeProcessor(InputProcessor inputProcessor);

    /**
     * Returns a list with the active processors.
     *
     * @return List<InputProcessor>
     */
    public List<InputProcessor> getProcessors();

    /**
     * The actual processed document's security context
     *
     * @return The SecurityContext
     */
    public SecurityContext getSecurityContext();

    /**
     * The actual processed document's document context
     *
     * @return The DocumentContext
     */
    public DocumentContext getDocumentContext();

    /**
     * Create a new SubChain. The XMLEvents will be only be processed from the given InputProcessor to the end.
     * All earlier InputProcessors don't get these events. In other words the chain will be splitted in two parts.
     *
     * @param inputProcessor The InputProcessor position the XMLEvents should be processed over this SubChain.
     * @return A new InputProcessorChain
     * @throws XMLStreamException  thrown when a streaming error occurs
     * @throws WSSecurityException thrown when a Security failure occurs
     */
    public InputProcessorChain createSubChain(InputProcessor inputProcessor) throws XMLStreamException, WSSecurityException;

    /**
     * Requests the next security header XMLEvent from the next processor in the chain.
     *
     * @return The next XMLEvent from the previous processor
     * @throws XMLStreamException  thrown when a streaming error occurs
     * @throws WSSecurityException thrown when a Security failure occurs
     */
    public XMLEvent processHeaderEvent() throws XMLStreamException, WSSecurityException;

    /**
     * Requests the next XMLEvent from the next processor in the chain.
     *
     * @return The next XMLEvent from the previous processor
     * @throws XMLStreamException  thrown when a streaming error occurs
     * @throws WSSecurityException thrown when a Security failure occurs
     */
    public XMLEvent processEvent() throws XMLStreamException, WSSecurityException;
}
