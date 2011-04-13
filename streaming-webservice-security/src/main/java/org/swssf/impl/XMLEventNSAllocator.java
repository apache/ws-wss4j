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
package org.swssf.impl;

import com.ctc.wstx.evt.DefaultEventAllocator;
import org.swssf.ext.ComparableAttribute;
import org.swssf.ext.ComparableNamespace;
import org.swssf.ext.XMLEventNS;

import javax.xml.namespace.QName;
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
 * todo this class needs some love...
 * <p/>
 * An extended XMLEventAllocator to collect namespaces and C14N relevant attributes
 *
 * @author $Author: giger $
 * @version $Revision: 281 $ $Date: 2011-01-04 21:15:27 +0100 (Tue, 04 Jan 2011) $
 */
public class XMLEventNSAllocator implements XMLEventAllocator {

    private XMLEventAllocator xmlEventAllocator = DefaultEventAllocator.getDefaultInstance();

    private ArrayDeque<List<ComparableNamespace>> nsStack = new ArrayDeque<List<ComparableNamespace>>(10);
    private ArrayDeque<List<ComparableAttribute>> attrStack = new ArrayDeque<List<ComparableAttribute>>(10);

    public XMLEventNSAllocator() {
    }

    private XMLEventNSAllocator(ArrayDeque<List<ComparableNamespace>> nsStack, ArrayDeque<List<ComparableAttribute>> attrStack) {
        this.nsStack = nsStack;
        this.attrStack = attrStack;
    }

    public XMLEventAllocator newInstance() {
        return new XMLEventNSAllocator(nsStack.clone(), attrStack.clone());
    }

    public XMLEvent allocate(XMLStreamReader reader) throws XMLStreamException {
        if (reader.getEventType() == XMLStreamConstants.START_ELEMENT) {

            List<ComparableNamespace> namespaceList = new LinkedList<ComparableNamespace>();

            for (int i = 0; i < reader.getNamespaceCount(); i++) {
                ComparableNamespace namespace;
                if (reader.getNamespacePrefix(i) == null) {
                    namespace = new ComparableNamespace(reader.getNamespaceURI(i));
                } else {
                    namespace = new ComparableNamespace(reader.getNamespacePrefix(i), reader.getNamespaceURI(i));
                }
                namespaceList.add(namespace);
            }

            List<ComparableAttribute> attributeList = new LinkedList<ComparableAttribute>();
            for (int i = 0; i < reader.getAttributeCount(); i++) {
                QName attrName = reader.getAttributeName(i);
                if (!"xml".equals(attrName.getPrefix())) {
                    if (!"".equals(attrName.getPrefix())) {
                        ComparableNamespace comparableNamespace = new ComparableNamespace(attrName.getPrefix(), attrName.getNamespaceURI());
                        namespaceList.add(comparableNamespace);
                    }
                    continue;
                }
                //add all attrs with xml - prefix (eg. xml:lang to attr list;
                ComparableAttribute attribute = new ComparableAttribute(attrName, reader.getAttributeValue(i));
                attributeList.add(attribute);
            }
            attrStack.push(attributeList);

            //add current ns also to the list if not already there
            ComparableNamespace comparableNamespace = new ComparableNamespace(reader.getName().getPrefix(), reader.getName().getNamespaceURI());
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
        return new XMLEventNS(xmlEventAllocator.allocate(reader), null, null);
    }

    public void allocate(XMLStreamReader reader, XMLEventConsumer consumer) throws XMLStreamException {
        xmlEventAllocator.allocate(reader, consumer);
    }
}
