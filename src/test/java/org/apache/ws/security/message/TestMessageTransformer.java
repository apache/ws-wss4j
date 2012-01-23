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

package org.apache.ws.security.message;

import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

import javax.xml.namespace.QName;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * Applies message transformations to the tests in
 * org.apache.ws.security.message.RequireSignedEncryptedDataElementsTest
 * 
 * @author <a href="mailto:alessio.soldano@jboss.com">Alessio Soldano</a>
 */
public class TestMessageTransformer extends org.junit.Assert {
    private static final org.apache.commons.logging.Log LOG = org.apache.commons.logging.LogFactory
        .getLog(TestMessageTransformer.class);

    public static Element duplicateEncryptedDataInWsseHeader(Element saaj, boolean moveReferenceList) {
        if (moveReferenceList) {
            moveReferenceList(saaj);
        }
        Element body = getFirstChildElement(saaj, new QName("http://schemas.xmlsoap.org/soap/envelope/",
                                                            "Body"), true);
        Element encData = getFirstChildElement(body, new QName("http://www.w3.org/2001/04/xmlenc#",
                                                               "EncryptedData"), true);
        Element newEncData = createNewEncryptedData(encData);
        Element sh = getFirstChildElement(saaj, new QName("http://schemas.xmlsoap.org/soap/envelope/",
                                                          "Header"), true);
        Element wsseHeader = getFirstChildElement(sh,
                                                  new QName(
                                                            "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd",
                                                            "Security"), true);

        Node newWsseHeader = wsseHeader.cloneNode(false);
        Node cur = wsseHeader.getFirstChild();

        String newId = newEncData.getAttributeNS(null, "Id");
        while (cur != null) {
            cur = copyHeadersAndUpdateRefList(cur, newWsseHeader, newId);
        }
        newWsseHeader.appendChild(newEncData);

        if (!moveReferenceList) {
            updateEncryptedKeyRefList(newWsseHeader, newId);
        }

        Node parent = wsseHeader.getParentNode();
        parent.removeChild(wsseHeader);
        parent.appendChild(newWsseHeader);
        print(saaj.getOwnerDocument());
        return newEncData;
    }

    public static Element duplicateEncryptedDataInWsseWrapperHeader(Element saaj, boolean moveReferenceList) {
        if (moveReferenceList) {
            moveReferenceList(saaj);
        }
        Element body = getFirstChildElement(saaj, new QName("http://schemas.xmlsoap.org/soap/envelope/",
                                                            "Body"), true);
        Element encData = getFirstChildElement(body, new QName("http://www.w3.org/2001/04/xmlenc#",
                                                               "EncryptedData"), true);
        Element newEncData = createNewEncryptedData(encData);
        Element sh = getFirstChildElement(saaj, new QName("http://schemas.xmlsoap.org/soap/envelope/",
                                                          "Header"), true);
        Element signature = getFirstChildElement(sh, new QName("http://www.w3.org/2000/09/xmldsig#",
                                                               "Signature"), true);

        Node wsseHeader = signature.getParentNode();
        Node newWsseHeader = wsseHeader.cloneNode(false);
        Node cur = wsseHeader.getFirstChild();
        String newId = newEncData.getAttributeNS(null, "Id");
        while (!cur.isSameNode(signature)) {
            cur = copyHeadersAndUpdateRefList(cur, newWsseHeader, newId);
        }
        Element wrapper = encData.getOwnerDocument().createElementNS(null, "a");
        wrapper.appendChild(newEncData);
        newWsseHeader.appendChild(wrapper);
        while (cur != null) {
            cur = copyHeadersAndUpdateRefList(cur, newWsseHeader, newId);
        }

        if (!moveReferenceList) {
            updateEncryptedKeyRefList(newWsseHeader, newId);
        }

        Node parent = wsseHeader.getParentNode();
        parent.removeChild(wsseHeader);
        parent.appendChild(newWsseHeader);
        print(saaj.getOwnerDocument());
        return newEncData;
    }

    public static Element duplicateEncryptedDataInExternalWrapperElement(Element saaj,
                                                                         boolean moveReferenceList) {
        if (moveReferenceList) {
            moveReferenceList(saaj);
        }
        Element body = getFirstChildElement(saaj, new QName("http://schemas.xmlsoap.org/soap/envelope/",
                                                            "Body"), true);
        Element encData = getFirstChildElement(body, new QName("http://www.w3.org/2001/04/xmlenc#",
                                                               "EncryptedData"), true);
        Element newEncData = createNewEncryptedData(encData);
        Element sh = getFirstChildElement(saaj, new QName("http://schemas.xmlsoap.org/soap/envelope/",
                                                          "Header"), true);
        Element wsseHeader = getFirstChildElement(sh,
                                                  new QName(
                                                            "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd",
                                                            "Security"), true);

        Node newWsseHeader = wsseHeader.cloneNode(false);
        Node cur = wsseHeader.getFirstChild();
        String newId = newEncData.getAttributeNS(null, "Id");
        while (cur != null) {
            cur = copyHeadersAndUpdateRefList(cur, newWsseHeader, newId);
        }
        sh.removeChild(wsseHeader);
        sh.appendChild(newWsseHeader);

        if (!moveReferenceList) {
            updateEncryptedKeyRefList(newWsseHeader, newId);
        }

        Element wrapper = encData.getOwnerDocument().createElementNS(null, "a");
        wrapper.setAttributeNS("http://schemas.xmlsoap.org/soap/envelope/", "mustUnderstand", "0");
        wrapper.setAttributeNS("http://schemas.xmlsoap.org/soap/envelope/", "actor", "foo");
        wrapper.appendChild(newEncData);
        sh.appendChild(wrapper);
        print(saaj.getOwnerDocument());
        return newEncData;
    }
    
    public static Element addEncryptedDataWithEmbeddedEncryptedKeyInWsseHeader(Element saaj) {
        moveReferenceList(saaj);
        Element body = getFirstChildElement(saaj, new QName("http://schemas.xmlsoap.org/soap/envelope/",
                                                            "Body"), true);
        Element encData = getFirstChildElement(body, new QName("http://www.w3.org/2001/04/xmlenc#",
                                                               "EncryptedData"), true);

        Element newEncData = (Element)encData.cloneNode(true);
        String newId = newEncData.getAttributeNS(null, "Id") + "b";
        newEncData.setAttributeNS(null, "Id", newId);

        Element encKey = getFirstChildElement(saaj, new QName("http://www.w3.org/2001/04/xmlenc#",
                                                              "EncryptedKey"), true);
        Element newEncKey = (Element)encKey.cloneNode(true);
        String newEcId = newEncKey.getAttributeNS(null, "Id") + "b";
        newEncKey.setAttributeNS(null, "Id", newEcId);

        Element keyInfo = getFirstChildElement(newEncData, new QName("http://www.w3.org/2000/09/xmldsig#",
                                                                     "KeyInfo"), true);
        Element str = getFirstChildElement(newEncData,
                                           new QName(
                                                     "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd",
                                                     "SecurityTokenReference"), true);
        keyInfo.replaceChild(newEncKey, str);

        Element wsseHeader = getFirstChildElement(saaj,
                                                  new QName(
                                                            "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd",
                                                            "Security"), true);

        Node newWsseHeader = wsseHeader.cloneNode(false);
        Node cur = wsseHeader.getFirstChild();

        while (cur != null) {
            cur = copyHeadersAndUpdateRefList(cur, newWsseHeader, newId);
        }
        newWsseHeader.appendChild(newEncData);

        Node parent = wsseHeader.getParentNode();
        parent.removeChild(wsseHeader);
        parent.appendChild(newWsseHeader);
        print(saaj.getOwnerDocument());
        return newEncData;

    }

    private static void moveReferenceList(Element saaj) {
        Element sh = getFirstChildElement(saaj, new QName("http://schemas.xmlsoap.org/soap/envelope/",
                                                          "Header"), true);
        Element encKey = getFirstChildElement(sh, new QName("http://www.w3.org/2001/04/xmlenc#",
                                                            "EncryptedKey"), true);
        Element refList = getFirstChildElement(encKey, new QName("http://www.w3.org/2001/04/xmlenc#",
                                                                 "ReferenceList"), true);

        Node wsseHeader = encKey.getParentNode();
        encKey.removeChild(refList);
        wsseHeader.appendChild(refList);
    }

    private static void updateEncryptedKeyRefList(Node wsseHeader, String newId) {
        Element encryptedKey = getFirstChildElement(wsseHeader,
                                                    new QName("http://www.w3.org/2001/04/xmlenc#",
                                                              "EncryptedKey"), true);
        Element ref = getFirstChildElement(encryptedKey, new QName("http://www.w3.org/2001/04/xmlenc#",
                                                                   "DataReference"), true);
        Element newRef = (Element)ref.cloneNode(true);
        newRef.setAttributeNS(null, "URI", "#" + newId);
        ref.getParentNode().appendChild(newRef);
    }

    private static void print(Document doc) {
        if (LOG.isDebugEnabled()) {
            LOG.debug("After transformation....");
            String outputString = org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }
    }

    private static Element createNewEncryptedData(Element encData) {
        Element newEncData = (Element)encData.cloneNode(true);
        String id = newEncData.getAttributeNS(null, "Id");
        String newId = id + "b";
        newEncData.setAttributeNS(null, "Id", newId);
        return newEncData;
    }

    private static Node copyHeadersAndUpdateRefList(Node cur, Node dest, String newId) {
        Node temp = cur.cloneNode(true);
        dest.appendChild(temp);
        if (newId != null && temp.getNodeType() == Node.ELEMENT_NODE) {
            Element t = (Element)temp;
            if (t.getLocalName().equals("ReferenceList")) {
                Element ref = getFirstChildElement(t, new QName("http://www.w3.org/2001/04/xmlenc#",
                                                                "DataReference"), true);
                Element newRef = (Element)ref.cloneNode(true);
                newRef.setAttributeNS(null, "URI", "#" + newId);
                t.appendChild(newRef);
            }
        }
        return cur.getNextSibling();
    }

    private static Element getFirstChildElement(Node node, QName nodeName, boolean recursive) {
        Element childElement = null;
        Iterator<Element> it = getChildElements(node, nodeName, recursive).iterator();
        if (it.hasNext()) {
            childElement = (Element)it.next();
        }
        return childElement;
    }

    private static List<Element> getChildElements(Node node, QName nodeName, boolean recursive) {
        List<Element> list = new LinkedList<Element>();

        NodeList nlist = node.getChildNodes();
        int len = nlist.getLength();
        for (int i = 0; i < len; i++) {
            Node child = nlist.item(i);
            if (child.getNodeType() == Node.ELEMENT_NODE) {
                search(list, (Element)child, nodeName, recursive);
            }
        }
        return list;
    }

    private static void search(List<Element> list, Element baseElement, QName nodeName, boolean recursive) {
        if (nodeName == null) {
            list.add(baseElement);
        } else {
            QName qname;
            if (nodeName.getNamespaceURI().length() > 0) {
                qname = new QName(baseElement.getNamespaceURI(), baseElement.getLocalName());
            } else {
                qname = new QName(baseElement.getLocalName());
            }
            if (qname.equals(nodeName)) {
                list.add(baseElement);
            }
        }
        if (recursive) {
            NodeList nlist = baseElement.getChildNodes();
            int len = nlist.getLength();
            for (int i = 0; i < len; i++) {
                Node child = nlist.item(i);
                if (child.getNodeType() == Node.ELEMENT_NODE) {
                    search(list, (Element)child, nodeName, recursive);
                }
            }
        }
    }

}
