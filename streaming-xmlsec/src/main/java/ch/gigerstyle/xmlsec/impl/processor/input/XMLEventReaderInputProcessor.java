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
package ch.gigerstyle.xmlsec.impl.processor.input;

import ch.gigerstyle.xmlsec.ext.*;

import javax.xml.stream.XMLEventReader;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.XMLEvent;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class XMLEventReaderInputProcessor extends AbstractInputProcessor {

    private XMLEventReader xmlEventReader;

    public XMLEventReaderInputProcessor(SecurityProperties securityProperties, XMLEventReader xmlEventReader) {
        super(securityProperties);
        setPhase(Constants.Phase.PREPROCESSING);
        this.xmlEventReader = xmlEventReader;
    }

    @Override
    public XMLEvent processNextHeaderEvent(InputProcessorChain inputProcessorChain) throws XMLStreamException, XMLSecurityException {
        XMLEvent xmlEvent = xmlEventReader.nextEvent();
        if (xmlEvent.isStartElement()) {
            inputProcessorChain.getDocumentContext().addPathElement(xmlEvent.asStartElement().getName());
        } else if (xmlEvent.isEndElement()) {
            inputProcessorChain.getDocumentContext().removePathElement();
        }
        return xmlEvent;
    }

    @Override
    public XMLEvent processNextEvent(InputProcessorChain inputProcessorChain) throws XMLStreamException, XMLSecurityException {
        XMLEvent xmlEvent = xmlEventReader.nextEvent();
        if (xmlEvent.isStartElement()) {
            inputProcessorChain.getDocumentContext().addPathElement(xmlEvent.asStartElement().getName());
        } else if (xmlEvent.isEndElement()) {
            inputProcessorChain.getDocumentContext().removePathElement();
        }
        return xmlEvent;
    }

    @Override
    public void doFinal(InputProcessorChain inputProcessorChain) throws XMLStreamException, XMLSecurityException {
        //nothing to-do. Also don't call super.doFinal() we are the last processor
    }
}
