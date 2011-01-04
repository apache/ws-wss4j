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
 * @author $Author: giger $
 * @version $Revision: 281 $ $Date: 2011-01-04 21:15:27 +0100 (Tue, 04 Jan 2011) $
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

    /**
     * Returns all Namespaces in the current scope
     * @return The Namespaces as List
     */
    public List<ComparableNamespace>[] getNamespaceList() {
        return namespaceList;
    }

    /**
     * Returns all C14N relevant Attributes in the current scope
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
