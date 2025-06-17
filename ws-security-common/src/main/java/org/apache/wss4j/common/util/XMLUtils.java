/**
L * Licensed to the Apache Software Foundation (ASF) under one
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
import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.AccessibleObject;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.xml.XMLConstants;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.sax.SAXSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;

import org.apache.wss4j.common.SOAP11Constants;
import org.apache.wss4j.common.SOAP12Constants;
import org.apache.wss4j.common.SOAPConstants;
import org.apache.wss4j.common.WSS4JConstants;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.w3c.dom.Attr;
import org.w3c.dom.CDATASection;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.Text;
import org.xml.sax.InputSource;

public final class XMLUtils {

    public static final String XMLNS_NS = "http://www.w3.org/2000/xmlns/";
    public static final String XML_NS = "http://www.w3.org/XML/1998/namespace";
    public static final String WSU_NS =
        "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";

    private static final org.slf4j.Logger LOG =
        org.slf4j.LoggerFactory.getLogger(XMLUtils.class);

    private static boolean isSAAJ14 = false;

    private XMLUtils() {
        // complete
    }

    private static final ClassValue<Method> GET_DOM_ELEMENTS_METHODS = new ClassValue<Method>() {
        @Override
        protected Method computeValue(Class<?> type) {
            try {
                return getMethod(type, "getDomElement");
            } catch (NoSuchMethodException e) {
                //best effort to try, do nothing if NoSuchMethodException
                return null;
            }
        }
    };

    private static final ClassValue<Method> GET_ENVELOPE_METHODS = new ClassValue<Method>() {
        @Override
        protected Method computeValue(Class<?> type) {
            try {
                return getMethod(type, "getEnvelope");
            } catch (NoSuchMethodException e) {
                //best effort to try, do nothing if NoSuchMethodException
                return null;
            }
        }
    };

    static {
        try {
            Method[] methods = XMLUtils.class.getClassLoader().
                loadClass("com.sun.xml.messaging.saaj.soap.SOAPDocumentImpl").getMethods();
            for (Method method : methods) {
                if (method.getName().equals("register")) {
                    //this is the 1.4+ SAAJ impl
                    isSAAJ14 = true;
                    break;
                }
            }
        } catch (ClassNotFoundException cnfe) {
            LOG.debug("Can't load class com.sun.xml.messaging.saaj.soap.SOAPDocumentImpl", cnfe);

            try {
                Method[] methods = XMLUtils.class.getClassLoader().
                    loadClass("com.sun.xml.internal.messaging.saaj.soap.SOAPDocumentImpl").getMethods();
                for (Method method : methods) {
                    if (method.getName().equals("register")) {
                        //this is the SAAJ impl in JDK9
                        isSAAJ14 = true;
                        break;
                    }
                }
            } catch (ClassNotFoundException cnfe1) {
                LOG.debug("can't load class com.sun.xml.internal.messaging.saaj.soap.SOAPDocumentImpl", cnfe1);
            }
        }
    }

    private static Method getMethod(final Class<?> clazz, final String name,
                                   final Class<?>... parameterTypes) throws NoSuchMethodException {
        try {
            return AccessController.doPrivileged(new PrivilegedExceptionAction<Method>() {
                public Method run() throws Exception {
                    return clazz.getMethod(name, parameterTypes);
                }
            });
        } catch (PrivilegedActionException pae) {
            Exception e = pae.getException();
            if (e instanceof NoSuchMethodException) {
                throw (NoSuchMethodException)e;
            }
            throw new SecurityException(e);
        }
    }

    private static <T extends AccessibleObject> T setAccessible(final T o) {
        return AccessController.doPrivileged(new PrivilegedAction<T>() {
            public T run() {
                o.setAccessible(true);
                return o;
            }
        });
    }



    /**
     * Gets a direct child with specified localname and namespace. <p/>
     *
     * @param parentNode the node where to start the search
     * @param localName local name of the child to get
     * @param namespace the namespace of the child to get
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

    /**
     * Return the text content of an Element, or null if no such text content exists
     */
    public static String getElementText(Element e) {
        if (e != null) {
            Node node = e.getFirstChild();
            StringBuilder builder = new StringBuilder();
            boolean found = false;
            while (node != null) {
                if (Node.TEXT_NODE == node.getNodeType()) {
                    found = true;
                    builder.append(((Text)node).getData());
                } else if (Node.CDATA_SECTION_NODE == node.getNodeType()) {
                    found = true;
                    builder.append(((CDATASection)node).getData());
                }
                node = node.getNextSibling();
            }

            if (!found) {
                return null;
            }
            return builder.toString();
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

    public static String prettyDocumentToString(Document doc) throws IOException, TransformerException {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            elementToStream(doc.getDocumentElement(), baos);
            return new String(baos.toByteArray(), StandardCharsets.UTF_8);
        }
    }

    public static void elementToStream(Element element, OutputStream out)
        throws TransformerException {
        DOMSource source = new DOMSource(element);
        StreamResult result = new StreamResult(out);

        TransformerFactory transFactory = TransformerFactory.newInstance();
        transFactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        try {
            transFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            transFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
        } catch (IllegalArgumentException ex) { //NOPMD
            // ignore
        }

        Transformer transformer = transFactory.newTransformer();
        transformer.transform(source, result);
    }

    /**
     * Utility to get the bytes uri
     *
     * @param source the resource to get
     */
    public static InputSource sourceToInputSource(Source source) throws IOException, TransformerException {
        if (source instanceof SAXSource) {
            return ((SAXSource) source).getInputSource();
        } else if (source instanceof DOMSource) {
            Node node = ((DOMSource) source).getNode();
            if (node instanceof Document) {
                node = ((Document) node).getDocumentElement();
            }
            Element domElement = (Element) node;
            try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
                elementToStream(domElement, baos);
                InputSource isource = new InputSource(source.getSystemId());
                isource.setByteStream(new ByteArrayInputStream(baos.toByteArray()));
                return isource;
            }
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

    /**
     * Set a namespace/prefix on an element if it is not set already. First off, it
     * searches for the element for the prefix associated with the specified
     * namespace. If the prefix isn't null, then this is returned. Otherwise, it
     * creates a new attribute using the namespace/prefix passed as parameters.
     *
     * @param element
     * @param namespace
     * @param prefix
     * @return the prefix associated with the set namespace
     */
    public static String setNamespace(Element element, String namespace, String prefix) {
        String pre = getPrefixNS(namespace, element);
        if (pre != null) {
            return pre;
        }
        element.setAttributeNS(XMLNS_NS, "xmlns:" + prefix, namespace);
        return prefix;
    }

    public static String getPrefixNS(String uri, Node e) {
        while (e != null && e.getNodeType() == Element.ELEMENT_NODE) {
            NamedNodeMap attrs = e.getAttributes();
            int length = attrs.getLength();
            for (int n = 0; n < length; n++) {
                Attr a = (Attr) attrs.item(n);
                String name = a.getName();
                if (name.startsWith("xmlns:") && a.getNodeValue().equals(uri)) {
                    return name.substring("xmlns:".length());
                }
            }
            e = e.getParentNode();
        }
        return null;
    }

    /**
     * Turn a reference (eg "#5") into an ID (eg "5").
     *
     * @param ref
     * @return ref trimmed and with the leading "#" removed, or null if not
     *         correctly formed
     */
    public static String getIDFromReference(String ref) {
        if (ref == null) {
            return null;
        }
        String id = ref.trim();
        if (id.length() == 0) {
            return null;
        }
        if (id.charAt(0) == '#') {
            id = id.substring(1);
        }
        return id;
    }

    /**
     * Returns the single element that contains an Id with value
     * <code>uri</code> and <code>namespace</code>. The Id can be either a wsu:Id or an Id
     * with no namespace. This is a replacement for a XPath Id lookup with the given namespace.
     * It's somewhat faster than XPath, and we do not deal with prefixes, just with the real
     * namespace URI
     *
     * If checkMultipleElements is true and there are multiple elements, we LOG.a
     * warning and return null as this can be used to get around the signature checking.
     *
     * @param startNode Where to start the search
     * @param value Value of the Id attribute
     * @param checkMultipleElements If true then go through the entire tree and return
     *        null if there are multiple elements with the same Id
     * @return The found element if there was exactly one match, or
     *         <code>null</code> otherwise
     */
    public static Element findElementById(
        Node startNode, String value, boolean checkMultipleElements
    ) {
        //
        // Replace the formerly recursive implementation with a depth-first-loop lookup
        //
        if (startNode == null) {
            return null;
        }
        Node startParent = startNode.getParentNode();
        Node processedNode = null;
        Element foundElement = null;
        String id = XMLUtils.getIDFromReference(value);

        while (startNode != null && id != null) {
            // start node processing at this point
            if (startNode.getNodeType() == Node.ELEMENT_NODE) {
                Element se = (Element) startNode;
                // Try the wsu:Id first
                String attributeNS = se.getAttributeNS(WSU_NS, "Id");
                if (attributeNS.length() == 0 || !id.equals(attributeNS)) {
                    attributeNS = se.getAttributeNS(null, "Id");
                }
                if (attributeNS.length() != 0 && id.equals(attributeNS)) {
                    if (!checkMultipleElements) {
                        return se;
                    } else if (foundElement == null) {
                        foundElement = se; // Continue searching to find duplicates
                    } else {
                        LOG.warn("Multiple elements with the same 'Id' attribute value!");
                        return null;
                    }
                }
            }

            processedNode = startNode;
            startNode = startNode.getFirstChild();

            // no child, this node is done.
            if (startNode == null) {
                // close node processing, get sibling
                startNode = processedNode.getNextSibling();
            }
            // no more siblings, get parent, all children
            // of parent are processed.
            while (startNode == null) {
                processedNode = processedNode.getParentNode();
                if (processedNode == startParent) {
                    return foundElement;
                }
                // close parent node processing (processed node now)
                startNode = processedNode.getNextSibling();
            }
        }
        return foundElement;
    }


    /**
     * Returns the first element that matches <code>name</code> and
     * <code>namespace</code>. <p/> This is a replacement for a XPath lookup
     * <code>//name</code> with the given namespace. It's somewhat faster than
     * XPath, and we do not deal with prefixes, just with the real namespace URI
     *
     * @param startNode Where to start the search
     * @param name Local name of the element
     * @param namespace Namespace URI of the element
     * @return The found element or <code>null</code>
     */
    public static Element findElement(Node startNode, String name, String namespace) {
        //
        // Replace the formerly recursive implementation with a depth-first-loop
        // lookup
        //
        if (startNode == null) {
            return null;
        }
        Node startParent = startNode.getParentNode();
        Node processedNode = null;

        while (startNode != null) {
            // start node processing at this point
            if (startNode.getNodeType() == Node.ELEMENT_NODE
                && startNode.getLocalName().equals(name)) {
                String ns = startNode.getNamespaceURI();
                if (ns != null && ns.equals(namespace)) {
                    return (Element)startNode;
                }

                if ((namespace == null || namespace.length() == 0)
                    && (ns == null || ns.length() == 0)) {
                    return (Element)startNode;
                }
            }
            processedNode = startNode;
            startNode = startNode.getFirstChild();

            // no child, this node is done.
            if (startNode == null) {
                // close node processing, get sibling
                startNode = processedNode.getNextSibling();
            }
            // no more siblings, get parent, all children
            // of parent are processed.
            while (startNode == null) {
                processedNode = processedNode.getParentNode();
                if (processedNode == startParent) {
                    return null;
                }
                // close parent node processing (processed node now)
                startNode = processedNode.getNextSibling();
            }
        }
        return null;
    }

    /**
     * Returns all elements that match <code>name</code> and <code>namespace</code>.
     * <p/> This is a replacement for a XPath lookup
     * <code>//name</code> with the given namespace. It's somewhat faster than
     * XPath, and we do not deal with prefixes, just with the real namespace URI
     *
     * @param startNode Where to start the search
     * @param name Local name of the element
     * @param namespace Namespace URI of the element
     * @return The found elements (or an empty list)
     */
    public static List<Element> findElements(Node startNode, String name, String namespace) {
        //
        // Replace the formerly recursive implementation with a depth-first-loop
        // lookup
        //
        if (startNode == null) {
            return Collections.emptyList();
        }
        Node startParent = startNode.getParentNode();
        Node processedNode = null;

        List<Element> foundNodes = new ArrayList<>();
        while (startNode != null) {
            // start node processing at this point
            if (startNode.getNodeType() == Node.ELEMENT_NODE
                && startNode.getLocalName().equals(name)) {
                String ns = startNode.getNamespaceURI();
                if (ns != null && ns.equals(namespace)) {
                    foundNodes.add((Element)startNode);
                }

                if ((namespace == null || namespace.length() == 0)
                    && (ns == null || ns.length() == 0)) {
                    foundNodes.add((Element)startNode);
                }
            }
            processedNode = startNode;
            startNode = startNode.getFirstChild();

            // no child, this node is done.
            if (startNode == null) {
                // close node processing, get sibling
                startNode = processedNode.getNextSibling();
            }
            // no more siblings, get parent, all children
            // of parent are processed.
            while (startNode == null) {
                processedNode = processedNode.getParentNode();
                if (processedNode == startParent) {
                    return foundNodes;
                }
                // close parent node processing (processed node now)
                startNode = processedNode.getNextSibling();
            }
        }
        return foundNodes;
    }

    /**
     * Returns the single SAMLAssertion element that contains an AssertionID/ID that
     * matches the supplied parameter.
     *
     * @param startNode Where to start the search
     * @param value Value of the AssertionID/ID attribute
     * @return The found element if there was exactly one match, or
     *         <code>null</code> otherwise
     */
    public static Element findSAMLAssertionElementById(Node startNode, String value) {
        Element foundElement = null;

        //
        // Replace the formerly recursive implementation with a depth-first-loop
        // lookup
        //
        if (startNode == null || value == null) {
            return null;
        }
        Node startParent = startNode.getParentNode();
        Node processedNode = null;

        while (startNode != null) {
            // start node processing at this point
            if (startNode.getNodeType() == Node.ELEMENT_NODE) {
                Element se = (Element) startNode;
                if (se.hasAttributeNS(null, "ID") && value.equals(se.getAttributeNS(null, "ID"))
                    || se.hasAttributeNS(null, "AssertionID")
                        && value.equals(se.getAttributeNS(null, "AssertionID"))) {
                    if (foundElement == null) {
                        foundElement = se; // Continue searching to find duplicates
                    } else {
                        LOG.warn("Multiple elements with the same 'ID' attribute value!");
                        return null;
                    }
                }
            }

            processedNode = startNode;
            startNode = startNode.getFirstChild();

            // no child, this node is done.
            if (startNode == null) {
                // close node processing, get sibling
                startNode = processedNode.getNextSibling();
            }
            // no more siblings, get parent, all children
            // of parent are processed.
            while (startNode == null) {
                processedNode = processedNode.getParentNode();
                if (processedNode == startParent) {
                    return foundElement;
                }
                // close parent node processing (processed node now)
                startNode = processedNode.getNextSibling();
            }
        }
        return foundElement;
    }

    /**
     * find the first ws-security header block <p/>
     *
     * @param doc the DOM document (SOAP request)
     * @param envelope the SOAP envelope
     * @param doCreate if true create a new WSS header block if none exists
     * @return the WSS header or null if none found and doCreate is false
     */
    public static Element findWsseSecurityHeaderBlock(
        Document doc,
        Element envelope,
        boolean doCreate
    ) throws WSSecurityException {
        return findWsseSecurityHeaderBlock(doc, envelope, null, doCreate);
    }

    /**
     * find a WS-Security header block for a given actor <p/>
     *
     * @param doc the DOM document (SOAP request)
     * @param envelope the SOAP envelope
     * @param actor the actor (role) name of the WSS header
     * @param doCreate if true create a new WSS header block if none exists
     * @return the WSS header or null if none found and doCreate is false
     */
    public static Element findWsseSecurityHeaderBlock(
        Document doc,
        Element envelope,
        String actor,
        boolean doCreate
    ) throws WSSecurityException {
        String soapNamespace = getSOAPNamespace(doc.getDocumentElement());
        Element header =
            XMLUtils.getDirectChildElement(
                doc.getDocumentElement(),
                WSS4JConstants.ELEM_HEADER,
                soapNamespace
            );
        if (header == null) { // no SOAP header at all
            if (doCreate) {
                if (isSAAJ14) {
                    try {
                        Node node = null;
                        Method method = GET_ENVELOPE_METHODS.get(doc.getClass());
                        if (method != null) {
                            try {
                                node = (Node)setAccessible(method).invoke(doc);
                            } catch (IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
                                throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY);
                            }
                        }
                        if (node != null) {
                            header = createElementInSameNamespace(node, WSS4JConstants.ELEM_HEADER);
                        } else {
                            header = createElementInSameNamespace(doc.getDocumentElement(), WSS4JConstants.ELEM_HEADER);
                        }
                        header = (Element)doc.importNode(header, true);
                        header = (Element)getDomElement(header);
                        header = prependChildElement(envelope, header);

                    } catch (Exception e) {
                        throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY);
                    }

                } else {
                    header = createElementInSameNamespace(envelope, WSS4JConstants.ELEM_HEADER);
                    header = prependChildElement(envelope, header);
                }
            } else {
                return null;
            }
        }

        String actorLocal = WSS4JConstants.ATTR_ACTOR;
        if (WSS4JConstants.URI_SOAP12_ENV.equals(soapNamespace)) {
            actorLocal = WSS4JConstants.ATTR_ROLE;
        }

        //
        // Iterate through the security headers
        //
        Element foundSecurityHeader = null;
        for (
            Node currentChild = header.getFirstChild();
            currentChild != null;
            currentChild = currentChild.getNextSibling()
        ) {
            if (Node.ELEMENT_NODE == currentChild.getNodeType()
                && WSS4JConstants.WSSE_LN.equals(currentChild.getLocalName())
                && WSS4JConstants.WSSE_NS.equals(currentChild.getNamespaceURI())) {

                Element elem = (Element)currentChild;
                Attr attr = elem.getAttributeNodeNS(soapNamespace, actorLocal);
                String hActor = (attr != null) ? attr.getValue() : null;

                if (isActorEqual(actor, hActor)) {
                    if (foundSecurityHeader != null) {
                        LOG.debug(
                            "Two or more security headers have the same actor name: {}", actor
                        );
                        throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY);
                    }
                    foundSecurityHeader = elem;
                }
            }
        }
        if (foundSecurityHeader != null) {
            return foundSecurityHeader;
        } else if (doCreate) {
            foundSecurityHeader = doc.createElementNS(WSS4JConstants.WSSE_NS, "wsse:Security");
            foundSecurityHeader.setAttributeNS(WSS4JConstants.XMLNS_NS, "xmlns:wsse", WSS4JConstants.WSSE_NS);
            foundSecurityHeader = (Element)doc.importNode(foundSecurityHeader, true);
            foundSecurityHeader = (Element)getDomElement(foundSecurityHeader);

            return prependChildElement(header, foundSecurityHeader);
        }
        return null;
    }

    /**
     * create a new element in the same namespace <p/>
     *
     * @param parent for the new element
     * @param localName of the new element
     * @return the new element
     */
    private static Element createElementInSameNamespace(Node parent, String localName) {
        String qName = localName;
        String prefix = parent.getPrefix();
        if (prefix != null && prefix.length() > 0) {
            qName = prefix + ":" + localName;
        }

        String nsUri = parent.getNamespaceURI();
        return parent.getOwnerDocument().createElementNS(nsUri, qName);
    }

    /**
     * prepend a child element <p/>
     *
     * @param parent element of this child element
     * @param child the element to append
     * @return the child element
     */
    public static Element prependChildElement(
        Element parent,
        Element child
    ) {
        Node firstChild = parent.getFirstChild();
        Element domChild = null;
        try {
            domChild = (Element)getDomElement(child);
        } catch (WSSecurityException e) {
            LOG.debug("Error when try to get Dom Element from the child", e);
        }
        if (firstChild == null) {
            return (Element)parent.appendChild(domChild);
        } else {
            return (Element)parent.insertBefore(domChild, firstChild);
        }
    }

    /**
     * Try to get the DOM Node from the SAAJ Node with JAVA9
     * @param node The original node we need check
     * @return The DOM node
     * @throws WSSecurityException
     */
    private static Node getDomElement(Node node) throws WSSecurityException {
        if (node != null && isSAAJ14) {

            Method method = GET_DOM_ELEMENTS_METHODS.get(node.getClass());
            if (method != null) {
                try {
                    return (Node)setAccessible(method).invoke(node);
                } catch (IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
                    throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY);
                }
            }
        }
        return node;
    }

    /**
     * Compares two actor strings and returns true if these are equal. Takes
     * care of the null length strings and uses ignore case.
     *
     * @param actor
     * @param hActor
     * @return true is the actor arguments are equal
     */
    public static boolean isActorEqual(String actor, String hActor) {
        if ((hActor == null || hActor.length() == 0)
            && (actor == null || actor.length() == 0)) {
            return true;
        }

        return hActor != null && actor != null && hActor.equalsIgnoreCase(actor);
    }

    public static SOAPConstants getSOAPConstants(Element startElement) {
        Document doc = startElement.getOwnerDocument();
        String ns = doc.getDocumentElement().getNamespaceURI();
        if (WSS4JConstants.URI_SOAP12_ENV.equals(ns)) {
            return new SOAP12Constants();
        }
        return new SOAP11Constants();
    }

    public static String getSOAPNamespace(Element startElement) {
        return getSOAPConstants(startElement).getEnvelopeURI();
    }

    /**
     * Register the jakarta.xml.soap.Node with new Cloned Dom Node with java9
     * @param doc The SOAPDocumentImpl
     * @param clonedElement The cloned Element
     * @return new clonedElement which already associated with the SAAJ Node
     * @throws WSSecurityException
     */
    public static Element cloneElement(Document doc, Element clonedElement) throws WSSecurityException {
        clonedElement = (Element)clonedElement.cloneNode(true);
        if (isSAAJ14) {
            // here we need register the jakarta.xml.soap.Node with new instance
            clonedElement = (Element)doc.importNode(clonedElement, true);
            clonedElement = (Element)getDomElement(clonedElement);
        }
        return clonedElement;
    }
}
