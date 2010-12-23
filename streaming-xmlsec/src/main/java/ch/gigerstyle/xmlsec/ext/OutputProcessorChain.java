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

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public interface OutputProcessorChain extends ProcessorChain {

    public SecurityContext getSecurityContext();

    public void addProcessor(OutputProcessor outputProcessor);

    public void removeProcessor(OutputProcessor outputProcessor);

    /**
     * Creates a subchain starts with the outputProcessor + 1
     * Holding a reference to a subchain in a processor and access it in different methods is
     * strictly forbidden. Abusing this rule leads to undefined state (Most probably to a ArrayIndexOutOfBounds exception)
     *
     * @param outputProcessor
     * @return
     * @throws XMLStreamException
     * @throws XMLSecurityException
     */
    public OutputProcessorChain createSubChain(OutputProcessor outputProcessor) throws XMLStreamException, XMLSecurityException;

    public void processEvent(XMLEvent xmlEvent) throws XMLStreamException, XMLSecurityException;
}