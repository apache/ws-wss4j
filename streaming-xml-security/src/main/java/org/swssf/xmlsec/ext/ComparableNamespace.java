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

    private String prefix = "";
    private String uri;

    public ComparableNamespace(String uri) {
        this.uri = uri;
    }

    public ComparableNamespace(String prefix, String uri) {
        if (prefix != null) {
            this.prefix = prefix;
        }
        this.uri = uri;
    }

    public int compareTo(ComparableNamespace o) {
        //An element's namespace nodes are sorted lexicographically by local name
        //(the default namespace node, if one exists, has no local name and is therefore lexicographically least).
        return this.prefix.compareTo(o.getPrefix());
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof ComparableNamespace)) {
            return false;
        }
        ComparableNamespace comparableNamespace = (ComparableNamespace) obj;

        if (comparableNamespace.getPrefix().equals(this.prefix)) {
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
        return false;
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
        if (this.prefix == null || this.prefix.isEmpty()) {
            return "xmlns=\"" + this.uri + "\"";
        }
        return "xmlns:" + this.prefix + "=\"" + this.uri + "\"";
    }
}
