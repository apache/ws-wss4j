package ch.gigerstyle.xmlsec.ext;

import ch.gigerstyle.xmlsec.impl.XMLEventNSAllocator;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.XMLEvent;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * User: giger
 * Date: May 30, 2010
 * Time: 7:29:28 PM
 * Copyright 2010 Marc Giger gigerstyle@gmx.ch
 * <p/>
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 * <p/>
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * <p/>
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */
public abstract class AbstractOutputProcessor implements OutputProcessor {

    protected final transient Log logger = LogFactory.getLog(this.getClass());

    protected SecurityProperties securityProperties;
    private QName lastStartElementName = new QName("", "");

    private Constants.Phase phase = Constants.Phase.PROCESSING;
    private Set<String> beforeProcessors = new HashSet<String>();
    private Set<String> afterProcessors = new HashSet<String>();

    protected AbstractOutputProcessor(SecurityProperties securityProperties) throws XMLSecurityException {
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

    public abstract void processEvent(XMLEvent xmlEvent, OutputProcessorChain outputProcessorChain, SecurityContext securityContext) throws XMLStreamException, XMLSecurityException;

    public void processNextEvent(XMLEvent xmlEvent, OutputProcessorChain outputProcessorChain, SecurityContext securityContext) throws XMLStreamException, XMLSecurityException {
        if (xmlEvent.isStartElement()) {
            lastStartElementName = xmlEvent.asStartElement().getName();
        }
        processEvent(xmlEvent, outputProcessorChain, securityContext);
    }

    public void doFinal(OutputProcessorChain outputProcessorChain, SecurityContext securityContext) throws XMLStreamException, XMLSecurityException {
        outputProcessorChain.doFinal();
    }

    public SecurityProperties getSecurityProperties() {
        return securityProperties;
    }

    public QName getLastStartElementName() {
        return lastStartElementName;
    }

    public static void createStartElementAndOutputAsEvent(OutputProcessorChain outputProcessorChain, QName element, Map<QName, String> attributes) throws XMLStreamException, XMLSecurityException {
        XMLEvent xmlEvent = outputProcessorChain.getSecurityContext().<XMLEventNSAllocator>get("XMLEventNSAllocator").createStartElement(element, attributes);
        outputAsEvent(outputProcessorChain, xmlEvent);
    }

    public static void createEndElementAndOutputAsEvent(OutputProcessorChain outputProcessorChain, QName element) throws XMLStreamException, XMLSecurityException {
        final XMLEvent xmlEvent = outputProcessorChain.getSecurityContext().<XMLEventNSAllocator>get("XMLEventNSAllocator").createEndElement(element);
        outputAsEvent(outputProcessorChain, xmlEvent);
    }

    public static void createCharactersAndOutputAsEvent(OutputProcessorChain outputProcessorChain, String characters) throws XMLStreamException, XMLSecurityException {
        final XMLEvent xmlEvent = outputProcessorChain.getSecurityContext().<XMLEventNSAllocator>get("XMLEventNSAllocator").createCharacters(characters);
        outputAsEvent(outputProcessorChain, xmlEvent);
    }

    public static void outputAsEvent(OutputProcessorChain outputProcessorChain, XMLEvent xmlEvent) throws XMLStreamException, XMLSecurityException {
        outputProcessorChain.reset();
        outputProcessorChain.processEvent(xmlEvent);
    }
}
