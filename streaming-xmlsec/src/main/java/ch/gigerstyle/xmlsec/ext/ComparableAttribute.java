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
package ch.gigerstyle.xmlsec.ext;

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
