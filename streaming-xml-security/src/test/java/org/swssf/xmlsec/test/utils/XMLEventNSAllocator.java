/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.swssf.xmlsec.test.utils;

import org.swssf.xmlsec.ext.ComparableAttribute;
import org.swssf.xmlsec.ext.ComparableNamespace;
import org.swssf.xmlsec.ext.XMLEventNS;

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
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class XMLEventNSAllocator implements XMLEventAllocator {

    private XMLEventAllocator xmlEventAllocator;

    private ArrayDeque<List<ComparableNamespace>> nsStack;
    private ArrayDeque<List<ComparableAttribute>> attrStack;

    public XMLEventNSAllocator() throws Exception {
        this(new ArrayDeque<List<ComparableNamespace>>(10), new ArrayDeque<List<ComparableAttribute>>(10));
    }

    private XMLEventNSAllocator(ArrayDeque<List<ComparableNamespace>> nsStack, ArrayDeque<List<ComparableAttribute>> attrStack) throws Exception {
        XMLInputFactory xmlInputFactory = XMLInputFactory.newInstance();
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
