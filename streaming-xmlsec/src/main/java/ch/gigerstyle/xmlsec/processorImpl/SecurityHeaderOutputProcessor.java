package ch.gigerstyle.xmlsec.processorImpl;

import ch.gigerstyle.xmlsec.*;

import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.EndElement;
import javax.xml.stream.events.Namespace;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 * User: giger
 * Date: May 29, 2010
 * Time: 5:24:44 PM
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
public class SecurityHeaderOutputProcessor extends AbstractOutputProcessor {

    public SecurityHeaderOutputProcessor(SecurityProperties securityProperties) throws XMLSecurityException {
        super(securityProperties);
    }

    public void processEvent(XMLEvent xmlEvent, OutputProcessorChain outputProcessorChain, SecurityContext securityContext) throws XMLStreamException, XMLSecurityException {

        outputProcessorChain.processEvent(xmlEvent);

        if (xmlEvent.isStartElement()) {
            StartElement startElement = xmlEvent.asStartElement();

            if (startElement.getName().equals(Constants.TAG_soap11_Header)) {
                //todo replace all Constants.xmlEventFactory.create** with XMLEventAllocator.create*** @see signatureOutputProcessor
                //or better with create methods in abstractOuptutProcessor
                Namespace namespace = Constants.xmlEventFactory.createNamespace(Constants.TAG_wsse_Security.getPrefix(), Constants.TAG_wsse_Security.getNamespaceURI());
                List<Namespace> namespaceList = new ArrayList<Namespace>();
                namespaceList.add(namespace);
                Iterator namespaceIterator = namespaceList.iterator();
                XMLEvent newXMLEvent = Constants.xmlEventFactory.createStartElement(Constants.TAG_wsse_Security, null, namespaceIterator);
                OutputProcessorChain subOutputProcessorChain = outputProcessorChain.createSubChain(this);
                subOutputProcessorChain.processEvent(newXMLEvent);
                subOutputProcessorChain.reset();

                newXMLEvent = Constants.xmlEventFactory.createEndElement(Constants.TAG_wsse_Security, namespaceIterator);
                subOutputProcessorChain.processEvent(newXMLEvent);
                subOutputProcessorChain.reset();
            }
        }
        else if (xmlEvent.isEndElement()) {
            EndElement endElement = xmlEvent.asEndElement();

        }
    }

    @Override
    public void processHeaderEvent(XMLEvent xmlEvent, OutputProcessorChain outputProcessorChain, SecurityContext securityContext) throws XMLStreamException, XMLSecurityException {
        outputProcessorChain.processHeaderEvent(xmlEvent);
    }
}
