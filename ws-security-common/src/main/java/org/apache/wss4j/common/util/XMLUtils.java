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
package org.apache.wss4j.common.util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.OutputStream;

import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.sax.SAXSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;

import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.InputSource;

public final class XMLUtils {
    
    public static final String XMLNS_NS = "http://www.w3.org/2000/xmlns/";
    public static final String XML_NS = "http://www.w3.org/XML/1998/namespace";
    
    private XMLUtils() {
        // complete
    }

    /**
     * Gets a direct child with specified localname and namespace. <p/>
     *
     * @param parentNode the node where to start the search
     * @param localName  local name of the child to get
     * @param namespace  the namespace of the child to get
     * @return the node or <code>null</code> if not such node found
     */
    public static Element getDirectChildElement(Node parentNode, String localName, String namespace) {
        if (parentNode == null) {
            return null;
        }
        for (Node currentChild = parentNode.getFirstChild();
            currentChild != null;
            currentChild = currentChild.getNextSibling()
        ) {
            if (Node.ELEMENT_NODE == currentChild.getNodeType()
                    && localName.equals(currentChild.getLocalName())
                    && namespace.equals(currentChild.getNamespaceURI())) {
                return (Element) currentChild;
            }
        }
        return null;
    }
    
    public static String getNamespace(String prefix, Node e) {
        while (e != null && e.getNodeType() == Node.ELEMENT_NODE) {
            Attr attr = null;
            if (prefix == null) {
                attr = ((Element) e).getAttributeNode("xmlns");
            } else {
                attr = ((Element) e).getAttributeNodeNS(XMLNS_NS, prefix);
            }
            if (attr != null) {
                return attr.getValue();
            }
            e = e.getParentNode();
        }
        return null;
    }
    
    public static String PrettyDocumentToString(Document doc) throws TransformerException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ElementToStream(doc.getDocumentElement(), baos);
        return new String(baos.toByteArray());
    }

    public static void ElementToStream(Element element, OutputStream out) 
        throws TransformerException {
        DOMSource source = new DOMSource(element);
        StreamResult result = new StreamResult(out);
        TransformerFactory transFactory = TransformerFactory.newInstance();
        Transformer transformer = transFactory.newTransformer();
        transformer.transform(source, result);
    }

    /**
     * Utility to get the bytes uri
     *
     * @param source the resource to get
     */
    public static InputSource sourceToInputSource(Source source) throws TransformerException {
        if (source instanceof SAXSource) {
            return ((SAXSource) source).getInputSource();
        } else if (source instanceof DOMSource) {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            Node node = ((DOMSource) source).getNode();
            if (node instanceof Document) {
                node = ((Document) node).getDocumentElement();
            }
            Element domElement = (Element) node;
            ElementToStream(domElement, baos);
            InputSource isource = new InputSource(source.getSystemId());
            isource.setByteStream(new ByteArrayInputStream(baos.toByteArray()));
            return isource;
        } else if (source instanceof StreamSource) {
            StreamSource ss = (StreamSource) source;
            InputSource isource = new InputSource(ss.getSystemId());
            isource.setByteStream(ss.getInputStream());
            isource.setCharacterStream(ss.getReader());
            isource.setPublicId(ss.getPublicId());
            return isource;
        } else {
            return getInputSourceFromURI(source.getSystemId());
        }
    }

    /**
     * Utility to get the bytes uri.
     * Does NOT handle authenticated URLs,
     * use getInputSourceFromURI(uri, username, password)
     *
     * @param uri the resource to get
     */
    public static InputSource getInputSourceFromURI(String uri) {
        return new InputSource(uri);
    }
}
