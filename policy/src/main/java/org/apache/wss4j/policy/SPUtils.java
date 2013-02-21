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
package org.apache.wss4j.policy;

import org.w3c.dom.*;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class SPUtils {

    private SPUtils() {
    }

    public static boolean hasChildElements(Element element) {
        NodeList nodeList = element.getChildNodes();
        int elementCount = 0;
        for (int i = 0; i < nodeList.getLength(); i++) {
            Node node = nodeList.item(i);
            if (node.getNodeType() == Node.ELEMENT_NODE) {
                elementCount++;
            }
        }
        return elementCount > 0;
    }

    public static Element getFirstPolicyChildElement(Element element) {
        Element policy = getFirstChildElement(element, SPConstants.P_LOCALNAME);
        if (policy != null && org.apache.neethi.Constants.isPolicyNS(policy.getNamespaceURI())) {
            return policy;
        }
        return null;
    }

    public static boolean hasChildElementWithName(Element element, QName elementName) {
        Element child = SPUtils.getFirstChildElement(element, elementName);
        if (child != null) {
            return true;
        }
        return false;
    }

    public static Element getFirstChildElement(Node parent, String childNodeName) {
        Node node = parent.getFirstChild();
        while (node != null && (Node.ELEMENT_NODE != node.getNodeType()
                || !node.getLocalName().equals(childNodeName))) {
            node = node.getNextSibling();
        }
        return (Element) node;
    }

    public static Element getFirstChildElement(Node parent, QName childNodeName) {
        Node node = parent.getFirstChild();
        while (node != null && (Node.ELEMENT_NODE != node.getNodeType()
                || !(((node.getNamespaceURI() == null && childNodeName.getNamespaceURI() == null)
                || (node.getNamespaceURI() != null && node.getNamespaceURI().equals(childNodeName.getNamespaceURI())))
                && node.getLocalName().equals(childNodeName.getLocalPart())))) {
            node = node.getNextSibling();
        }
        return (Element) node;
    }

    public static String getFirstChildElementText(Node parent, QName childNodeName) {
        Element element = getFirstChildElement(parent, childNodeName);
        return element != null ? element.getTextContent() : null;
    }

    public static Element getFirstChildElement(Node parent) {
        Node node = parent.getFirstChild();
        while (node != null && Node.ELEMENT_NODE != node.getNodeType()) {
            node = node.getNextSibling();
        }
        return (Element) node;
    }

    public static Element getNextSiblingElement(Node node) {
        Node n = node.getNextSibling();
        while (n != null && Node.ELEMENT_NODE != n.getNodeType()) {
            n = n.getNextSibling();
        }
        return (Element) n;
    }

    public static boolean isOptional(Element element) {
        Attr attr = findOptionalAttribute(element);
        if (attr != null) {
            String v = attr.getValue();
            return "true".equalsIgnoreCase(v) || "1".equals(v);
        }
        return false;
    }

    public static Attr findOptionalAttribute(Element element) {
        NamedNodeMap attributes = element.getAttributes();
        for (int x = 0; x < attributes.getLength(); x++) {
            Attr attr = (Attr) attributes.item(x);
            QName qName = new QName(attr.getNamespaceURI(), attr.getLocalName());
            if (org.apache.neethi.Constants.isOptionalAttribute(qName)) {
                return attr;
            }
        }
        return null;
    }

    public static boolean isIgnorable(Element element) throws IllegalArgumentException {
        Attr attr = findIgnorableAttribute(element);
        if (attr != null) {
            String value = attr.getValue();
            if ("true".equalsIgnoreCase(value) || "1".equals(value)) {
                if (SP13Constants.SP_NS.equals(element.getNamespaceURI())) {
                    throw new IllegalArgumentException("Ignorable attribute not allowed. @see http://docs.oasis-open.org/ws-sx/ws-securitypolicy/v1.3/os/ws-securitypolicy-1.3-spec-os.html#_Toc212617792");
                }
                return true;
            }
        }
        return false;
    }

    public static Attr findIgnorableAttribute(Element element) {
        NamedNodeMap attributes = element.getAttributes();
        for (int x = 0; x < attributes.getLength(); x++) {
            Attr attr = (Attr) attributes.item(x);
            QName qName = new QName(attr.getNamespaceURI(), attr.getLocalName());
            if (org.apache.neethi.Constants.isIgnorableAttribute(qName)) {
                return attr;
            }
        }
        return null;
    }

    public static String getAttribute(Element element, QName attName) {
        Attr attr;
        if (attName.getNamespaceURI() == null || "".equals(attName.getNamespaceURI())) {
            attr = element.getAttributeNode(attName.getLocalPart());
        } else {
            attr = element.getAttributeNodeNS(attName.getNamespaceURI(), attName.getLocalPart());
        }
        return attr == null ? null : attr.getValue().trim();
    }

    public static QName getElementQName(Element element) {
        return new QName(element.getNamespaceURI(), element.getLocalName(), element.getPrefix());
    }

    public static void serialize(Node node, XMLStreamWriter xmlStreamWriter) throws XMLStreamException {
        if (node.getNodeType() == Node.DOCUMENT_NODE) {
            Document document = (org.w3c.dom.Document) node;
            serialize(document.getDocumentElement(), xmlStreamWriter);
        }
        if (node.getNodeType() == Node.ELEMENT_NODE) {
            Element element = (Element) node;
            xmlStreamWriter.writeStartElement(element.getPrefix(), element.getLocalName(), element.getNamespaceURI());
            NamedNodeMap namedNodeMap = element.getAttributes();
            for (int i = 0; i < namedNodeMap.getLength(); i++) {
                Attr attr = (Attr) namedNodeMap.item(i);
                String prefix = attr.getPrefix();
                if (prefix != null && "xmlns".equals(prefix)) {
                    xmlStreamWriter.writeNamespace(attr.getLocalName(), attr.getValue());
                } else if (prefix == null && "xmlns".equals(attr.getLocalName())) {
                    xmlStreamWriter.writeDefaultNamespace(attr.getValue());
                } else {
                    xmlStreamWriter.writeAttribute(prefix, attr.getNamespaceURI(), attr.getLocalName(), attr.getValue());
                }
            }
            //write ns after processing element namespaces to prevent redeclarations
            if (element.getPrefix() != null) {
                String ns = xmlStreamWriter.getNamespaceContext().getNamespaceURI(element.getPrefix());
                if (ns == null) {
                    xmlStreamWriter.writeNamespace(element.getPrefix(), element.getNamespaceURI());
                }
            }
            NodeList childNodes = element.getChildNodes();
            for (int i = 0; i < childNodes.getLength(); i++) {
                serialize(childNodes.item(i), xmlStreamWriter);
            }
            xmlStreamWriter.writeEndElement();
        } else if (node.getNodeType() == Node.TEXT_NODE) {
            Text text = (Text) node;
            xmlStreamWriter.writeCharacters(text.getData());
        }
    }
}
