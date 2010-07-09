package ch.gigerstyle.xmlsec;

import com.ctc.wstx.evt.DefaultEventAllocator;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.events.Attribute;
import javax.xml.stream.events.Characters;
import javax.xml.stream.events.Namespace;
import javax.xml.stream.events.XMLEvent;
import javax.xml.stream.util.XMLEventAllocator;
import javax.xml.stream.util.XMLEventConsumer;
import java.util.*;

/**
 * User: giger
 * Date: May 18, 2010
 * Time: 8:59:14 PM
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
public class XMLEventNSAllocator implements XMLEventAllocator {

    private XMLEventAllocator xmlEventAllocator = DefaultEventAllocator.getDefaultInstance();

    private Deque<List<ComparableNamespace>> nsStack = new ArrayDeque<List<ComparableNamespace>>();
    private Deque<List<ComparableAttribute>> attrStack = new ArrayDeque<List<ComparableAttribute>>();

    public XMLEventAllocator newInstance() {
        //always return the same instance, so that the stacks are preserved!
        return this;
    }

    public XMLEvent allocate(XMLStreamReader reader) throws XMLStreamException {
        if (reader.getEventType() == XMLStreamConstants.START_ELEMENT) {

            List<ComparableNamespace> namespaceList = new ArrayList<ComparableNamespace>();
            for (int i = 0; i < reader.getNamespaceCount(); i++) {
                Namespace namespace;
                if (reader.getNamespacePrefix(i) == null) {
                    namespace = Constants.xmlEventFactory.createNamespace(reader.getNamespaceURI(i));
                } else {
                    namespace = Constants.xmlEventFactory.createNamespace(reader.getNamespacePrefix(i), reader.getNamespaceURI(i));
                }
                ComparableNamespace comparableNamespace = new ComparableNamespace(namespace);
                namespaceList.add(comparableNamespace);
            }

            List<ComparableAttribute> attributeList = new ArrayList<ComparableAttribute>();
            for (int i = 0; i < reader.getAttributeCount(); i++) {
                QName attrName = reader.getAttributeName(i);
                if (!"xml".equals(attrName.getPrefix())) {
                    if (!"".equals(attrName.getPrefix())) {
                        ComparableNamespace comparableNamespace = new ComparableNamespace(Constants.xmlEventFactory.createNamespace(attrName.getPrefix(), attrName.getNamespaceURI()));
                        namespaceList.add(comparableNamespace);
                    }
                    continue;
                }
                //add all attrs with xml - prefix (eg. xml:lang to attr list;
                Attribute attribute = Constants.xmlEventFactory.createAttribute(attrName, reader.getAttributeValue(i));
                attributeList.add(new ComparableAttribute(attribute));
            }
            attrStack.push(attributeList);

            //add current ns also to the list if not already there
            Namespace namespace = Constants.xmlEventFactory.createNamespace(reader.getName().getPrefix(), reader.getName().getNamespaceURI());
            ComparableNamespace comparableNamespace = new ComparableNamespace(namespace);
            if (!namespaceList.contains(comparableNamespace)) {
                namespaceList.add(comparableNamespace);
            }
            nsStack.push(namespaceList);

            return new XMLEventNS(xmlEventAllocator.allocate(reader), nsStack.toArray(new List[nsStack.size()]), attrStack.toArray(new List[attrStack.size()]));

        } else if (reader.getEventType() == XMLStreamConstants.END_ELEMENT) {
            XMLEventNS xmlEventNS = new XMLEventNS(xmlEventAllocator.allocate(reader), nsStack.toArray(new List[nsStack.size()]), attrStack.toArray(new List[attrStack.size()]));
            nsStack.pop();
            attrStack.pop();
            return xmlEventNS;
        }
        return new XMLEventNS(xmlEventAllocator.allocate(reader), new List[0], new List[0]);
    }

    public void allocate(XMLStreamReader reader, XMLEventConsumer consumer) throws XMLStreamException {
        xmlEventAllocator.allocate(reader, consumer);
    }


    /*
        Begin allocation methods for output-processors
     */

    public XMLEvent createStartElement(QName element, Map<QName, String> attributes) throws XMLStreamException {

        List<String> prefixList = new ArrayList<String>();
        prefixList.add(element.getPrefix());

        List<Namespace> namespaceList = new ArrayList<Namespace>();
        Namespace curElementNamespace = Constants.xmlEventFactory.createNamespace(element.getPrefix(), element.getNamespaceURI());
        namespaceList.add(curElementNamespace);

        List<ComparableNamespace> comparableNamespaceList = new ArrayList<ComparableNamespace>();
        comparableNamespaceList.add(new ComparableNamespace(curElementNamespace));

        List<Attribute> attributeList = new ArrayList<Attribute>();
        List<ComparableAttribute> comparableAttributeList = new ArrayList<ComparableAttribute>();

        if (attributes != null) {
            Iterator<Map.Entry<QName, String>> attributesEntrySet = attributes.entrySet().iterator();
            while (attributesEntrySet.hasNext()) {
                Map.Entry<QName, String> qNameStringEntry = attributesEntrySet.next();
                Attribute attribute = Constants.xmlEventFactory.createAttribute(qNameStringEntry.getKey(), qNameStringEntry.getValue());
                attributeList.add(attribute);
                comparableAttributeList.add(new ComparableAttribute(attribute));
                String prefix = qNameStringEntry.getKey().getPrefix();
                if (!prefixList.contains(prefix)) {
                    /*
                    if (prefix != null && "".equals(prefix) && "".equals(attribute.getName().getNamespaceURI())) {
                        continue;
                    }
                    */
                    if (prefix != null && prefix.length() == 0 && attribute.getName().getNamespaceURI().length() == 0) {
                        continue;
                    }

                    prefixList.add(prefix);
                    Namespace tmpNameSpace = Constants.xmlEventFactory.createNamespace(prefix, qNameStringEntry.getKey().getNamespaceURI());
                    namespaceList.add(tmpNameSpace);
                    comparableNamespaceList.add(new ComparableNamespace(tmpNameSpace));
                }
            }
        }

        nsStack.push(comparableNamespaceList);
        attrStack.push(comparableAttributeList);

        //return Constants.xmlEventFactory.createStartElement(element, attributeList.iterator(), namespaceList.iterator());
        return new XMLEventNS(Constants.xmlEventFactory.createStartElement(element, attributeList.iterator(), namespaceList.iterator()), nsStack.toArray(new List[nsStack.size()]), attrStack.toArray(new List[attrStack.size()]));
    }

    public XMLEvent createStartElement(QName element, List<Namespace> namespaces, List<Attribute> attributes) throws XMLStreamException {

        List<String> prefixList = new ArrayList<String>();
        prefixList.add(element.getPrefix());

        List<Namespace> namespaceList = new ArrayList<Namespace>();
        List<ComparableNamespace> comparableNamespaceList = new ArrayList<ComparableNamespace>();

        Namespace curElementNamespace = Constants.xmlEventFactory.createNamespace(element.getPrefix(), element.getNamespaceURI());
        namespaceList.add(curElementNamespace);
        comparableNamespaceList.add(new ComparableNamespace(curElementNamespace));

        for (int i = 0; i < namespaces.size(); i++) {
            Namespace namespace = namespaces.get(i);
            String prefix = namespace.getPrefix();

            /*
            if (prefix != null && "".equals(prefix) && "".equals(namespace.getNamespaceURI())) {
                continue;
            }
            */
            if (prefix != null && prefix.length() == 0 && namespace.getNamespaceURI().length() == 0) {
                continue;
            }

            if (!prefixList.contains(prefix)) {
                prefixList.add(prefix);
                Namespace tmpNameSpace = Constants.xmlEventFactory.createNamespace(prefix, namespace.getNamespaceURI());
                namespaceList.add(tmpNameSpace);
                comparableNamespaceList.add(new ComparableNamespace(tmpNameSpace));
            }
        }

        List<Attribute> attributeList = new ArrayList<Attribute>();
        List<ComparableAttribute> comparableAttributeList = new ArrayList<ComparableAttribute>();
        for (int i = 0; i < attributes.size(); i++) {
            Attribute attribute = attributes.get(i);
            attributeList.add(attribute);
            comparableAttributeList.add(new ComparableAttribute(attribute));
            String prefix = attribute.getName().getPrefix();

            /*
            if (prefix != null && "".equals(prefix) && "".equals(attribute.getName().getNamespaceURI())) {
                continue;
            }             
            */
            if (prefix != null && prefix.length() == 0 && attribute.getName().getNamespaceURI().length() == 0) {
                continue;
            }

            if (!prefixList.contains(prefix)) {
                prefixList.add(prefix);
                Namespace tmpNameSpace = Constants.xmlEventFactory.createNamespace(prefix, attribute.getName().getNamespaceURI());
                namespaceList.add(tmpNameSpace);
                comparableNamespaceList.add(new ComparableNamespace(tmpNameSpace));
            }
        }

        nsStack.push(comparableNamespaceList);
        attrStack.push(comparableAttributeList);
        //todo we have a little problem;-) every call to createStartElement methods must have an equivalent call to createEndElement to hold the stack small and correct!!   
        /*
        System.out.println("NS Size: " + nsStack.size());
        System.out.println("Attr Size: " + attrStack.size());
        */
        return new XMLEventNS(Constants.xmlEventFactory.createStartElement(element, attributeList.iterator(), namespaceList.iterator()), nsStack.toArray(new List[nsStack.size()]), attrStack.toArray(new List[attrStack.size()]));
    }

    public XMLEvent createEndElement(QName element) {
        List<Namespace> namespaceList = new ArrayList<Namespace>();
        namespaceList.add(Constants.xmlEventFactory.createNamespace(element.getPrefix(), element.getNamespaceURI()));

        XMLEventNS xmlEventNS = new XMLEventNS(Constants.xmlEventFactory.createEndElement(element, namespaceList.iterator()), nsStack.toArray(new List[nsStack.size()]), attrStack.toArray(new List[attrStack.size()]));

        nsStack.pop();
        attrStack.pop();

        return xmlEventNS;
    }

    public Characters createCharacters(String characters) {
        return Constants.xmlEventFactory.createCharacters(characters);
    }

    public Attribute createAttribute(QName attribute, String attributeValue) {
        return Constants.xmlEventFactory.createAttribute(attribute, attributeValue);
    }

    public Namespace createNamespace(String prefix, String uri) {
        return Constants.xmlEventFactory.createNamespace(prefix, uri);
    }
}
