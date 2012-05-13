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
package org.swssf.xmlsec.ext;

import javax.xml.namespace.QName;
import javax.xml.stream.Location;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.Characters;
import javax.xml.stream.events.EndElement;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;
import java.io.Writer;
import java.util.List;

/**
 * A Customized XMLEvent class to provide all Namespaces and Attributes from the current scope
 *
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class XMLEventNS implements XMLEvent {

    private XMLEvent xmlEvent;
    private List<ComparableNamespace>[] namespaceList;
    private List<ComparableAttribute>[] attributeList;

    public XMLEventNS(XMLEvent xmlEvent, List<ComparableNamespace>[] namespaceList, List<ComparableAttribute>[] attributeList) {
        this.xmlEvent = xmlEvent;
        this.namespaceList = namespaceList;
        this.attributeList = attributeList;
    }

    /**
     * Returns all Namespaces in the current scope
     *
     * @return The Namespaces as List
     */
    public List<ComparableNamespace>[] getNamespaceList() {
        return namespaceList;
    }

    /**
     * Returns all C14N relevant Attributes in the current scope
     *
     * @return The Attributes as List
     */
    public List<ComparableAttribute>[] getAttributeList() {
        return attributeList;
    }

    public XMLEvent getCurrentEvent() {
        return xmlEvent;
    }

    public int getEventType() {
        return xmlEvent.getEventType();
    }

    public Location getLocation() {
        return xmlEvent.getLocation();
    }

    public boolean isStartElement() {
        return xmlEvent.isStartElement();
    }

    public boolean isAttribute() {
        return xmlEvent.isAttribute();
    }

    public boolean isNamespace() {
        return xmlEvent.isNamespace();
    }

    public boolean isEndElement() {
        return xmlEvent.isEndElement();
    }

    public boolean isEntityReference() {
        return xmlEvent.isEntityReference();
    }

    public boolean isProcessingInstruction() {
        return xmlEvent.isProcessingInstruction();
    }

    public boolean isCharacters() {
        return xmlEvent.isCharacters();
    }

    public boolean isStartDocument() {
        return xmlEvent.isStartDocument();
    }

    public boolean isEndDocument() {
        return xmlEvent.isEndDocument();
    }

    public StartElement asStartElement() {
        return xmlEvent.asStartElement();
    }

    public EndElement asEndElement() {
        return xmlEvent.asEndElement();
    }

    public Characters asCharacters() {
        return xmlEvent.asCharacters();
    }

    public QName getSchemaType() {
        return xmlEvent.getSchemaType();
    }

    public void writeAsEncodedUnicode(Writer writer) throws XMLStreamException {
        xmlEvent.writeAsEncodedUnicode(writer);
    }
}
