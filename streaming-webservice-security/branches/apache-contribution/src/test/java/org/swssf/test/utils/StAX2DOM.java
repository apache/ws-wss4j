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
package org.swssf.test.utils;

import org.w3c.dom.*;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.stream.Location;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class StAX2DOM {
    static final String XML_NS = "http://www.w3.org/2000/xmlns/";

    public static Document readDoc(DocumentBuilder documentBuilder, XMLStreamReader xmlStreamReader) throws XMLStreamException {
        //skip possible text at the beginning of a document and go directly to the root tag
        while (xmlStreamReader.hasNext() && xmlStreamReader.next() != XMLStreamConstants.START_ELEMENT) {
        }
        Document document = documentBuilder.newDocument();
        StAX2DOM.readDocElements(document, document, xmlStreamReader, false, false);
        xmlStreamReader.close();
        return document;
    }

    public static void readDocElements(Document doc, Node parent,
                                       XMLStreamReader reader, boolean repairing, boolean recordLoc)
            throws XMLStreamException {

        int event = reader.getEventType();
        while (reader.hasNext()) {
            switch (event) {
                case XMLStreamConstants.START_ELEMENT:
                    startElement(doc, parent, reader, repairing, recordLoc);
/*
                    if (parent instanceof Document) {
                        return;
                    }
*/
                    break;
                case XMLStreamConstants.END_DOCUMENT:
                    return;
                case XMLStreamConstants.END_ELEMENT:
                    return;
                case XMLStreamConstants.NAMESPACE:
                    break;
                case XMLStreamConstants.ATTRIBUTE:
                    break;
                case XMLStreamConstants.CHARACTERS:
                    if (parent != null) {
                        recordLoc = addLocation(doc,
                                parent.appendChild(doc.createTextNode(reader.getText())),
                                reader, recordLoc);
                    }
                    break;
                case XMLStreamConstants.COMMENT:
                    if (parent != null) {
                        parent.appendChild(doc.createComment(reader.getText()));
                    }
                    break;
                case XMLStreamConstants.CDATA:
                    recordLoc = addLocation(doc,
                            parent.appendChild(doc.createCDATASection(reader.getText())),
                            reader, recordLoc);
                    break;
                case XMLStreamConstants.PROCESSING_INSTRUCTION:
                    parent.appendChild(doc.createProcessingInstruction(reader.getPITarget(), reader.getPIData()));
                    break;
                case XMLStreamConstants.ENTITY_REFERENCE:
                    parent.appendChild(doc.createProcessingInstruction(reader.getPITarget(), reader.getPIData()));
                    break;
                default:
                    break;
            }

            if (reader.hasNext()) {
                event = reader.next();
            }
        }
    }

    static boolean addLocation(Document doc, Node node,
                               XMLStreamReader reader,
                               boolean recordLoc) {
        if (recordLoc) {
            Location loc = reader.getLocation();
            if (loc != null && (loc.getColumnNumber() != 0 || loc.getLineNumber() != 0)) {
                try {
                    final int charOffset = loc.getCharacterOffset();
                    final int colNum = loc.getColumnNumber();
                    final int linNum = loc.getLineNumber();
                    final String pubId = loc.getPublicId() == null ? doc.getDocumentURI() : loc.getPublicId();
                    final String sysId = loc.getSystemId() == null ? doc.getDocumentURI() : loc.getSystemId();
                    Location loc2 = new Location() {
                        public int getCharacterOffset() {
                            return charOffset;
                        }

                        public int getColumnNumber() {
                            return colNum;
                        }

                        public int getLineNumber() {
                            return linNum;
                        }

                        public String getPublicId() {
                            return pubId;
                        }

                        public String getSystemId() {
                            return sysId;
                        }
                    };
                    node.setUserData("location", loc2, new UserDataHandler() {
                        public void handle(short operation, String key, Object data, Node src, Node dst) {
                            if (operation == NODE_CLONED) {
                                dst.setUserData(key, data, this);
                            }
                        }
                    });
                } catch (Exception ex) {
                    //possibly not DOM level 3, won't be able to record this then
                    return false;
                }
            }
        }
        return recordLoc;
    }

    /**
     * @param parent
     * @param reader
     * @return
     * @throws javax.xml.stream.XMLStreamException
     *
     */
    static Element startElement(Document doc,
                                Node parent,
                                XMLStreamReader reader,
                                boolean repairing,
                                boolean recordLocation)
            throws XMLStreamException {

        Element e = doc.createElementNS(reader.getNamespaceURI(), reader.getLocalName());
        if (reader.getPrefix() != null) {
            e.setPrefix(reader.getPrefix());
        }
        e = (Element) parent.appendChild(e);
        recordLocation = addLocation(doc, e, reader, recordLocation);

        for (int ns = 0; ns < reader.getNamespaceCount(); ns++) {
            String uri = reader.getNamespaceURI(ns);
            String prefix = reader.getNamespacePrefix(ns);

            declare(e, uri, prefix);
        }

        for (int att = 0; att < reader.getAttributeCount(); att++) {
            String name = reader.getAttributeLocalName(att);
            String prefix = reader.getAttributePrefix(att);
            if (prefix != null && prefix.length() > 0) {
                name = prefix + ":" + name;
            }

            Attr attr = doc.createAttributeNS(reader.getAttributeNamespace(att), name);
            attr.setValue(reader.getAttributeValue(att));
            e.setAttributeNode(attr);
        }

        if (repairing && !isDeclared(e, reader.getNamespaceURI(), reader.getPrefix())) {
            declare(e, reader.getNamespaceURI(), reader.getPrefix());
        }

        reader.next();

        readDocElements(doc, e, reader, repairing, recordLocation);

        return e;
    }

    static void declare(Element node, String uri, String prefix) {
        String qualname;
        if (prefix != null && prefix.length() > 0) {
            qualname = "xmlns:" + prefix;
        } else {
            qualname = "xmlns";
        }
        Attr attr = node.getOwnerDocument().createAttributeNS(XML_NS, qualname);
        attr.setValue(uri);
        node.setAttributeNodeNS(attr);
    }

    static boolean isDeclared(Element e, String namespaceURI, String prefix) {
        Attr att;
        if (prefix != null && prefix.length() > 0) {
            att = e.getAttributeNodeNS(XML_NS, prefix);
        } else {
            att = e.getAttributeNode("xmlns");
        }

        if (att != null && att.getNodeValue().equals(namespaceURI)) {
            return true;
        }

        if (e.getParentNode() instanceof Element) {
            return isDeclared((Element) e.getParentNode(), namespaceURI, prefix);
        }

        return false;
    }
}
