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

/**
 * Basic interface for Output- and Input-Processor chains 
 * @author $Author$
 * @version $Revision$ $Date$
 */
public interface ProcessorChain {

    /**
     * resets the chain so that the next event will go again to the first processor in the chain.
     */
    public void reset();

    /**
     * Will finally be called when the whole document is processed
     * @throws XMLStreamException thrown when a streaming error occurs
     * @throws XMLSecurityException thrown when a Security failure occurs
     */
    public void doFinal() throws XMLStreamException, XMLSecurityException;
}
