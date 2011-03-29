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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.swssf.impl.XMLEventNSAllocator;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.XMLEvent;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * An abstract OutputProcessor class for reusabilty
 *
 * @author $Author: giger $
 * @version $Revision: 281 $ $Date: 2011-01-04 21:15:27 +0100 (Tue, 04 Jan 2011) $
 */
public abstract class AbstractOutputProcessor implements OutputProcessor {

    protected final transient Log logger = LogFactory.getLog(this.getClass());

    protected SecurityProperties securityProperties;

    private Constants.Phase phase = Constants.Phase.PROCESSING;
    private Set<String> beforeProcessors = new HashSet<String>();
    private Set<String> afterProcessors = new HashSet<String>();

    protected AbstractOutputProcessor(SecurityProperties securityProperties) throws WSSecurityException {
        this.securityProperties = securityProperties;
    }

    public Constants.Phase getPhase() {
        return phase;
    }

    public void setPhase(Constants.Phase phase) {
        this.phase = phase;
    }

    public Set<String> getBeforeProcessors() {
        return beforeProcessors;
    }

    public Set<String> getAfterProcessors() {
        return afterProcessors;
    }

    public abstract void processEvent(XMLEvent xmlEvent, OutputProcessorChain outputProcessorChain) throws XMLStreamException, WSSecurityException;

    public void processNextEvent(XMLEvent xmlEvent, OutputProcessorChain outputProcessorChain) throws XMLStreamException, WSSecurityException {
        processEvent(xmlEvent, outputProcessorChain);
    }

    public void doFinal(OutputProcessorChain outputProcessorChain) throws XMLStreamException, WSSecurityException {
        outputProcessorChain.doFinal();
    }

    public SecurityProperties getSecurityProperties() {
        return securityProperties;
    }

    public static void createStartElementAndOutputAsEvent(OutputProcessorChain outputProcessorChain, QName element, Map<QName, String> attributes) throws XMLStreamException, WSSecurityException {
        XMLEvent xmlEvent = outputProcessorChain.getSecurityContext().<XMLEventNSAllocator>get(Constants.XMLEVENT_NS_ALLOCATOR).createStartElement(element, attributes);
        outputAsEvent(outputProcessorChain, xmlEvent);
    }

    public static void createEndElementAndOutputAsEvent(OutputProcessorChain outputProcessorChain, QName element) throws XMLStreamException, WSSecurityException {
        final XMLEvent xmlEvent = outputProcessorChain.getSecurityContext().<XMLEventNSAllocator>get(Constants.XMLEVENT_NS_ALLOCATOR).createEndElement(element);
        outputAsEvent(outputProcessorChain, xmlEvent);
    }

    public static void createCharactersAndOutputAsEvent(OutputProcessorChain outputProcessorChain, String characters) throws XMLStreamException, WSSecurityException {
        final XMLEvent xmlEvent = outputProcessorChain.getSecurityContext().<XMLEventNSAllocator>get(Constants.XMLEVENT_NS_ALLOCATOR).createCharacters(characters);
        outputAsEvent(outputProcessorChain, xmlEvent);
    }

    public static void outputAsEvent(OutputProcessorChain outputProcessorChain, XMLEvent xmlEvent) throws XMLStreamException, WSSecurityException {
        outputProcessorChain.reset();
        outputProcessorChain.processEvent(xmlEvent);
    }
}
