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

import javax.xml.namespace.QName;
import javax.xml.stream.XMLEventFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.*;
import java.util.*;

/**
 * An abstract OutputProcessor class for reusabilty
 *
 * @author $Author: giger $
 * @version $Revision: 281 $ $Date: 2011-01-04 21:15:27 +0100 (Tue, 04 Jan 2011) $
 */
public abstract class AbstractOutputProcessor implements OutputProcessor {

    protected final transient Log logger = LogFactory.getLog(this.getClass());

    protected static final XMLEventFactory xmlEventFactory = XMLEventFactory.newFactory();
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

    protected XMLEventNS cloneStartElementEvent(XMLEvent xmlEvent, List<Attribute> attributeList) throws XMLStreamException {
        XMLEventNS xmlEventNS = (XMLEventNS) xmlEvent;
        if (!xmlEvent.isStartElement()) {
            return xmlEventNS;
        }

        List<ComparableNamespace>[] xmlEventNSNamespaces = xmlEventNS.getNamespaceList();
        List<ComparableAttribute>[] xmlEventNsAttributes = xmlEventNS.getAttributeList();

        List<ComparableNamespace> currentXmlEventNamespaces = xmlEventNSNamespaces[0];
        currentXmlEventNamespaces.add(new ComparableNamespace(xmlEvent.asStartElement().getName().getPrefix(), xmlEvent.asStartElement().getName().getNamespaceURI()));

        List<Namespace> namespaceList = new ArrayList<Namespace>();
        Iterator<Namespace> namespaceIterator = xmlEvent.asStartElement().getNamespaces();
        while (namespaceIterator.hasNext()) {
            Namespace namespace = namespaceIterator.next();
            namespaceList.add(createNamespace(namespace.getPrefix(), namespace.getNamespaceURI()));
        }

        for (int i = 0; i < attributeList.size(); i++) {
            Attribute attribute = attributeList.get(i);
            boolean found = false;
            for (int j = 0; j < namespaceList.size(); j++) {
                Namespace namespace = namespaceList.get(j);
                if (namespace.getPrefix() != null && attribute.getName().getPrefix() != null && namespace.getPrefix().equals(attribute.getName().getPrefix())) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                namespaceList.add(createNamespace(attribute.getName().getPrefix(), attribute.getName().getNamespaceURI()));
                currentXmlEventNamespaces.add(new ComparableNamespace(attribute.getName().getPrefix(), attribute.getName().getNamespaceURI()));
            }
        }

        StartElement startElement = xmlEventFactory.createStartElement(xmlEvent.asStartElement().getName(), attributeList.iterator(), namespaceList.iterator());

        return new XMLEventNS(startElement, xmlEventNSNamespaces, xmlEventNsAttributes);
    }

    protected void createStartElementAndOutputAsEvent(OutputProcessorChain outputProcessorChain, QName element, Map<QName, String> attributes) throws XMLStreamException, WSSecurityException {
        List<Namespace> namespaceList = new LinkedList<Namespace>();
        namespaceList.add(xmlEventFactory.createNamespace(element.getPrefix(), element.getNamespaceURI()));

        List<Attribute> attributeList = new LinkedList<Attribute>();
        if (attributes != null) {
            Iterator<Map.Entry<QName, String>> attributeIterator = attributes.entrySet().iterator();
            while (attributeIterator.hasNext()) {
                Map.Entry<QName, String> qNameStringEntry = attributeIterator.next();
                Attribute attribute = xmlEventFactory.createAttribute(qNameStringEntry.getKey(), qNameStringEntry.getValue());
                attributeList.add(attribute);

                if ("".equals(attribute.getName().getPrefix())) {
                    continue;
                }

                boolean found = false;
                for (int i = 0; i < namespaceList.size(); i++) {
                    Namespace namespace = namespaceList.get(i);
                    if (namespace.getPrefix() != null && attribute.getName().getPrefix() != null && namespace.getPrefix().equals(attribute.getName().getPrefix())) {
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    namespaceList.add(xmlEventFactory.createNamespace(attribute.getName().getPrefix(), attribute.getName().getNamespaceURI()));
                }
            }
        }

        StartElement startElement = xmlEventFactory.createStartElement(element, attributeList.iterator(), namespaceList.iterator());
        outputAsEvent(outputProcessorChain, startElement);
    }

    protected EndElement createEndElement(QName element) {
        List<Namespace> namespaceList = new LinkedList<Namespace>();
        namespaceList.add(xmlEventFactory.createNamespace(element.getPrefix(), element.getNamespaceURI()));
        return xmlEventFactory.createEndElement(element, namespaceList.iterator());
    }

    protected void createEndElementAndOutputAsEvent(OutputProcessorChain outputProcessorChain, QName element) throws XMLStreamException, WSSecurityException {
        outputAsEvent(outputProcessorChain, createEndElement(element));
    }

    protected void createCharactersAndOutputAsEvent(OutputProcessorChain outputProcessorChain, String characters) throws XMLStreamException, WSSecurityException {
        outputAsEvent(outputProcessorChain, createCharacters(characters));
    }

    protected Characters createCharacters(String characters) {
        return xmlEventFactory.createCharacters(characters);
    }

    protected Attribute createAttribute(QName attribute, String attributeValue) {
        return xmlEventFactory.createAttribute(attribute, attributeValue);
    }

    protected Namespace createNamespace(String prefix, String uri) {
        return xmlEventFactory.createNamespace(prefix, uri);
    }

    protected void outputAsEvent(OutputProcessorChain outputProcessorChain, XMLEvent xmlEvent) throws XMLStreamException, WSSecurityException {
        outputProcessorChain.reset();
        outputProcessorChain.processEvent(xmlEvent);
    }
}
