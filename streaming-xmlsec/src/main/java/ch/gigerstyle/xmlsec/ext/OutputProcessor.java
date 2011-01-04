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
package ch.gigerstyle.xmlsec.ext;

import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.XMLEvent;
import java.util.Set;

/**
 * This is the Interface which every OutputProcessor must implement. 
 * @author $Author$
 * @version $Revision$ $Date$
 */
public interface OutputProcessor {

    /**
     * This OutputProcessor will be added before the processors in this set
     * @return The set with the named OutputProcessor
     */
    Set<String> getBeforeProcessors();

    /**
     * This OutputProcessor will be added after the processors in this set
     * @return The set with the named OutputProcessor
     */
    Set<String> getAfterProcessors();

    /**
     * The Phase in which this OutputProcessor should be applied
     * @return The Phase
     */
    Constants.Phase getPhase();

    /**
     * Will be called from the framework for every XMLEvent
     * @param xmlEvent The next XMLEvent to process
     * @param outputProcessorChain
     * @throws XMLStreamException thrown when a streaming error occurs
     * @throws XMLSecurityException thrown when a Security failure occurs
     */
    void processNextEvent(XMLEvent xmlEvent, OutputProcessorChain outputProcessorChain) throws XMLStreamException, XMLSecurityException;

    /**
     * Will be called when the whole document is processed.
     * @param outputProcessorChain
     * @throws XMLStreamException thrown when a streaming error occurs
     * @throws XMLSecurityException thrown when a Security failure occurs
     */
    void doFinal(OutputProcessorChain outputProcessorChain) throws XMLStreamException, XMLSecurityException;
}
