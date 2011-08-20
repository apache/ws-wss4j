/**
 * Copyright 2010, 2011 Marc Giger
 *
 * This file is part of the streaming-webservice-security-framework (swssf).
 *
 * The streaming-webservice-security-framework is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * The streaming-webservice-security-framework is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with the streaming-webservice-security-framework.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.swssf.ext;

import javax.xml.namespace.QName;
import javax.xml.stream.Location;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.Characters;
import javax.xml.stream.events.EndElement;
import javax.xml.stream.events.Namespace;
import javax.xml.stream.events.StartElement;
import java.io.Writer;

/**
 * Class to let XML-Namespaces be comparable how it is requested by C14N
 *
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class ComparableNamespace implements Namespace, Comparable<ComparableNamespace> {

    private String prefix;
    private String uri;

    public ComparableNamespace(String uri) {
        this.uri = uri;
        this.prefix = "";
    }

    public ComparableNamespace(String prefix, String uri) {
        if (prefix != null) {
            this.prefix = prefix;
        } else {
            this.prefix = "";
        }
        if (uri != null) {
            this.uri = uri;
        } else {
            this.uri = "";
        }
    }

    public int compareTo(ComparableNamespace o) {
        //An element's namespace nodes are sorted lexicographically by local name
        //(the default namespace node, if one exists, has no local name and is therefore lexicographically least).
        return this.getPrefix().compareTo(o.getPrefix());
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof ComparableNamespace)) {
            return false;
        }
        ComparableNamespace comparableNamespace = (ComparableNamespace) obj;

        if (comparableNamespace.getPrefix().equals(this.getPrefix())) {
            //just test for prefix to get the last prefix definition on the stack and let overwrite it 
            return true;
        }
        return false;
    }

    public QName getName() {
        return null;
    }

    public String getValue() {
        return null;
    }

    public String getNamespaceURI() {
        return uri;
    }

    public String getPrefix() {
        return prefix;
    }

    public boolean isDefaultNamespaceDeclaration() {
        return (prefix.length() == 0);
    }

    public String getDTDType() {
        return "CDATA";
    }

    public boolean isSpecified() {
        return true;
    }

    public int getEventType() {
        return NAMESPACE;
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
        return true;
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

    @Override
    public String toString() {
        if (getPrefix() == null || getPrefix().length() == 0) {
            return "xmlns=\"" + getNamespaceURI() + "\"";
        }
        return "xmlns:" + getPrefix() + "=\"" + getNamespaceURI() + "\"";
    }
}
