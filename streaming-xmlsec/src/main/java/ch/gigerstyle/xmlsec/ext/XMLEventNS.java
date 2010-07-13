package ch.gigerstyle.xmlsec.ext;

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
 * User: giger
 * Date: May 18, 2010
 * Time: 10:28:19 PM
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
public class XMLEventNS implements XMLEvent {

    private XMLEvent xmlEvent;
    private List<ComparableNamespace>[] namespaceList;
    List<ComparableAttribute>[] attributeList;

    public XMLEventNS(XMLEvent xmlEvent, List<ComparableNamespace>[] namespaceList, List<ComparableAttribute>[] attributeList) {
        this.xmlEvent = xmlEvent;
        this.namespaceList = namespaceList;
        this.attributeList = attributeList;
    }

    public List<ComparableNamespace>[] getNamespaceList() {
        return namespaceList;
    }

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
