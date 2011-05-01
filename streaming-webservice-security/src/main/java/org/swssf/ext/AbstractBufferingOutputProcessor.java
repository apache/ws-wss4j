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
import javax.xml.stream.events.EndElement;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;
import java.util.ArrayDeque;
import java.util.Iterator;

/**
 * An abstract OutputProcessor class for reusabilty
 *
 * @author $Author: giger $
 * @version $Revision: 281 $ $Date: 2011-01-04 21:15:27 +0100 (Tue, 04 Jan 2011) $
 */
public abstract class AbstractBufferingOutputProcessor extends AbstractOutputProcessor {

    private ArrayDeque<XMLEvent> xmlEventBuffer = new ArrayDeque<XMLEvent>();

    protected AbstractBufferingOutputProcessor(SecurityProperties securityProperties) throws WSSecurityException {
        super(securityProperties);
    }

    @Override
    public void processEvent(XMLEvent xmlEvent, OutputProcessorChain outputProcessorChain) throws XMLStreamException, WSSecurityException {
        xmlEventBuffer.push(xmlEvent);
    }

    @Override
    public void doFinal(OutputProcessorChain outputProcessorChain) throws XMLStreamException, WSSecurityException {
        OutputProcessorChain subOutputProcessorChain = outputProcessorChain.createSubChain(this);

        Iterator<XMLEvent> xmlEventIterator = xmlEventBuffer.descendingIterator();
        while (xmlEventIterator.hasNext()) {
            XMLEvent xmlEvent = xmlEventIterator.next();
            if (xmlEvent.isStartElement()) {
                StartElement startElement = xmlEvent.asStartElement();
                if (startElement.getName().equals(Constants.TAG_wsse_Security)
                        && Utils.isResponsibleActorOrRole(
                        startElement,
                        subOutputProcessorChain.getDocumentContext().getSOAPMessageVersionNamespace(),
                        getSecurityProperties().getActor())) {
                    subOutputProcessorChain.getDocumentContext().setInSecurityHeader(true);
                    subOutputProcessorChain.reset();
                    subOutputProcessorChain.processEvent(xmlEvent);
                    processHeaderEvent(subOutputProcessorChain);
                    break;
                }
            }
            subOutputProcessorChain.reset();
            subOutputProcessorChain.processEvent(xmlEvent);
        }
        while (xmlEventIterator.hasNext()) {
            XMLEvent xmlEvent = xmlEventIterator.next();
            if (xmlEvent.isEndElement()) {
                EndElement endElement = xmlEvent.asEndElement();
                if (endElement.getName().equals(Constants.TAG_wsse_Security)) {
                    subOutputProcessorChain.getDocumentContext().setInSecurityHeader(false);
                    subOutputProcessorChain.reset();
                    subOutputProcessorChain.processEvent(xmlEvent);
                    break;
                }
            }
            subOutputProcessorChain.reset();
            subOutputProcessorChain.processEvent(xmlEvent);
        }
        while (xmlEventIterator.hasNext()) {
            XMLEvent xmlEvent = xmlEventIterator.next();
            subOutputProcessorChain.reset();
            subOutputProcessorChain.processEvent(xmlEvent);
        }
        subOutputProcessorChain.reset();
        subOutputProcessorChain.doFinal();
        subOutputProcessorChain.removeProcessor(this);
    }

    protected abstract void processHeaderEvent(OutputProcessorChain outputProcessorChain) throws XMLStreamException, WSSecurityException;
}
