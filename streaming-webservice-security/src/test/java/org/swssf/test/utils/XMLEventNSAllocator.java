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
package org.swssf.test.utils;

import org.swssf.ext.ComparableAttribute;
import org.swssf.ext.ComparableNamespace;
import org.swssf.ext.XMLEventNS;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.events.XMLEvent;
import javax.xml.stream.util.XMLEventAllocator;
import javax.xml.stream.util.XMLEventConsumer;
import java.util.ArrayDeque;
import java.util.LinkedList;
import java.util.List;

/**
 * <p/>
 * An extended XMLEventAllocator to collect namespaces and C14N relevant attributes
 *
 * @author $Author: giger $
 * @version $Revision: 281 $ $Date: 2011-01-04 21:15:27 +0100 (Tue, 04 Jan 2011) $
 */
public class XMLEventNSAllocator implements XMLEventAllocator {

    private XMLEventAllocator xmlEventAllocator;

    private ArrayDeque<List<ComparableNamespace>> nsStack;
    private ArrayDeque<List<ComparableAttribute>> attrStack;

    public XMLEventNSAllocator() throws Exception {
        this(new ArrayDeque<List<ComparableNamespace>>(10), new ArrayDeque<List<ComparableAttribute>>(10));
    }

    private XMLEventNSAllocator(ArrayDeque<List<ComparableNamespace>> nsStack, ArrayDeque<List<ComparableAttribute>> attrStack) throws Exception {
        XMLInputFactory xmlInputFactory = XMLInputFactory.newFactory();
        if (xmlInputFactory.getClass().getName().equals("com.sun.xml.internal.stream.XMLInputFactoryImpl")) {
            xmlEventAllocator = (XMLEventAllocator) Class.forName("com.sun.xml.internal.stream.events.XMLEventAllocatorImpl").newInstance();
        } else if (xmlInputFactory.getClass().getName().equals("com.ctc.wstx.stax.WstxInputFactory")) {
            xmlEventAllocator = (XMLEventAllocator) Class.forName("com.ctc.wstx.evt.DefaultEventAllocator").getMethod("getDefaultInstance").invoke(null);
        } else {
            throw new Exception("Unknown XMLEventAllocator");
        }

        this.nsStack = nsStack;
        this.attrStack = attrStack;
    }

    public XMLEventAllocator newInstance() {
        try {
            return new XMLEventNSAllocator(nsStack.clone(), attrStack.clone());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @SuppressWarnings("unchecked")
    public XMLEvent allocate(XMLStreamReader reader) throws XMLStreamException {
        if (reader.getEventType() == XMLStreamConstants.START_ELEMENT) {

            List<String> prefixList = new LinkedList<String>();
            prefixList.add(reader.getPrefix());

            List<ComparableNamespace> comparableNamespaceList = new LinkedList<ComparableNamespace>();

            //add current nsto the list
            ComparableNamespace curElementNamespace = new ComparableNamespace(reader.getName().getPrefix(), reader.getName().getNamespaceURI());
            comparableNamespaceList.add(curElementNamespace);

            for (int i = 0; i < reader.getNamespaceCount(); i++) {
                String prefix = reader.getNamespacePrefix(i);
                String namespaceURI = reader.getNamespaceURI(i);
                if (prefix != null && prefix.length() == 0 && namespaceURI.length() == 0) {
                    continue;
                }

                if (!prefixList.contains(prefix)) {
                    prefixList.add(prefix);
                    ComparableNamespace tmpNameSpace = new ComparableNamespace(prefix, namespaceURI);
                    comparableNamespaceList.add(tmpNameSpace);
                }
            }

            List<ComparableAttribute> comparableAttributeList = new LinkedList<ComparableAttribute>();

            for (int i = 0; i < reader.getAttributeCount(); i++) {
                QName attrName = reader.getAttributeName(i);

                if (attrName.getPrefix() != null && attrName.getPrefix().length() == 0 && attrName.getNamespaceURI().length() == 0) {
                    continue;
                }

                if (!"xml".equals(attrName.getPrefix())) {
                    if (!"".equals(attrName.getPrefix())) {
                        ComparableNamespace comparableNamespace = new ComparableNamespace(attrName.getPrefix(), attrName.getNamespaceURI());
                        comparableNamespaceList.add(comparableNamespace);
                    }
                    continue;
                }
                //add all attrs with xml - prefix (eg. xml:lang to attr list;
                comparableAttributeList.add(new ComparableAttribute(attrName, reader.getAttributeValue(i)));
            }

            attrStack.push(comparableAttributeList);
            nsStack.push(comparableNamespaceList);
            return new XMLEventNS(xmlEventAllocator.allocate(reader), nsStack.toArray(new List[nsStack.size()]), attrStack.toArray(new List[attrStack.size()]));
        } else if (reader.getEventType() == XMLStreamConstants.END_ELEMENT) {
            XMLEventNS xmlEventNS = new XMLEventNS(xmlEventAllocator.allocate(reader), nsStack.toArray(new List[nsStack.size()]), attrStack.toArray(new List[attrStack.size()]));
            nsStack.pop();
            attrStack.pop();
            return xmlEventNS;
        }
        return xmlEventAllocator.allocate(reader);
    }

    public void allocate(XMLStreamReader reader, XMLEventConsumer consumer) throws XMLStreamException {
        xmlEventAllocator.allocate(reader, consumer);
    }
}
