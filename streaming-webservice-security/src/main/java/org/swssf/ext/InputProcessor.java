/**
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.swssf.ext;

import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.XMLEvent;
import java.util.Set;

/**
 * This is the Interface which every InputProcessor must implement.
 *
 * @author $Author: giger $
 * @version $Revision: 281 $ $Date: 2011-01-04 21:15:27 +0100 (Tue, 04 Jan 2011) $
 */
public interface InputProcessor {

    /**
     * This InputProcessor will be added before the processors in this set
     *
     * @return The set with the named InputProcessors
     */
    Set<Object> getBeforeProcessors();

    /**
     * This InputProcessor will be added after the processors in this set
     *
     * @return The set with the named InputProcessors
     */
    Set<Object> getAfterProcessors();

    /**
     * The Phase in which this InputProcessor should be applied
     *
     * @return The Phase
     */
    Constants.Phase getPhase();

    /**
     * Will be called from the framework when the next security-header XMLEvent is requested
     *
     * @param inputProcessorChain
     * @return The next XMLEvent
     * @throws XMLStreamException  thrown when a streaming error occurs
     * @throws WSSecurityException thrown when a Security failure occurs
     */
    XMLEvent processNextHeaderEvent(InputProcessorChain inputProcessorChain) throws XMLStreamException, WSSecurityException;

    /**
     * Will be called from the framework when the next XMLEvent is requested
     *
     * @param inputProcessorChain
     * @return The next XMLEvent
     * @throws XMLStreamException  thrown when a streaming error occurs
     * @throws WSSecurityException thrown when a Security failure occurs
     */
    XMLEvent processNextEvent(InputProcessorChain inputProcessorChain) throws XMLStreamException, WSSecurityException;

    /**
     * Will be called when the whole document is processed.
     *
     * @param inputProcessorChain
     * @throws XMLStreamException  thrown when a streaming error occurs
     * @throws WSSecurityException thrown when a Security failure occurs
     */
    void doFinal(InputProcessorChain inputProcessorChain) throws XMLStreamException, WSSecurityException;
}
