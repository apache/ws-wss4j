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
import javax.xml.stream.events.Attribute;
import javax.xml.stream.events.Characters;
import javax.xml.stream.events.EndElement;
import javax.xml.stream.events.StartElement;
import java.io.Writer;

/**
 * Class to let XML-Attributes be comparable how it is requested by C14N
 *
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class ComparableAttribute implements Attribute, Comparable<ComparableAttribute> {

    private QName name;
    private String value;

    public ComparableAttribute(QName name, String value) {
        this.name = name;
        this.value = value;
    }

    public int compareTo(ComparableAttribute o) {
        //An element's attribute nodes are sorted lexicographically with namespace URI as the primary
        //key and local name as the secondary key (an empty namespace URI is lexicographically least).
        int namespacePartCompare = this.getName().getNamespaceURI().compareTo(o.getName().getNamespaceURI());
        if (namespacePartCompare != 0) {
            return namespacePartCompare;
        } else {
            return this.getName().getLocalPart().compareTo(o.getName().getLocalPart());
        }
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof ComparableAttribute)) {
            return false;
        }
        ComparableAttribute comparableAttribute = (ComparableAttribute) obj;
        if (comparableAttribute.getName().getLocalPart().equals(this.getName().getLocalPart())) {
            //&& comparableNamespace.getNamespace().getNamespaceURI().equals(this.attribute.getNamespaceURI())) {
            return true;
        }
        return false;
    }

    public QName getName() {
        return name;
    }

    public String getValue() {
        return value;
    }

    public String getDTDType() {
        return "CDATA";
    }

    public boolean isSpecified() {
        return true;
    }

    public int getEventType() {
        return ATTRIBUTE;
    }

    public Location getLocation() {
        return null;
    }

    public boolean isStartElement() {
        return false;
    }

    public boolean isAttribute() {
        return true;
    }

    public boolean isNamespace() {
        return false;
    }

    public boolean isEndElement() {
        return false;
    }

    public boolean isEntityReference() {
        return false;
    }

    public boolean isProcessingInstruction() {
        return false;
    }

    public boolean isCharacters() {
        return false;
    }

    public boolean isStartDocument() {
        return false;
    }

    public boolean isEndDocument() {
        return false;
    }

    public StartElement asStartElement() {
        return null;
    }

    public EndElement asEndElement() {
        return null;
    }

    public Characters asCharacters() {
        return null;
    }

    public QName getSchemaType() {
        return null;
    }

    public void writeAsEncodedUnicode(Writer writer) throws XMLStreamException {
        throw new UnsupportedOperationException("writeAsEncodedUnicode not implemented");
    }
}
