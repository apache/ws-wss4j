/*
 * Copyright  2003-2004 The Apache Software Foundation.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package org.apache.ws.security.message;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.SOAPConstants;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.util.WSSecurityUtil;
import org.apache.xml.security.signature.XMLSignatureInput;
import org.apache.xml.security.utils.XMLUtils;
import org.apache.xml.security.utils.resolver.ResourceResolverException;
import org.apache.xml.security.utils.resolver.ResourceResolverSpi;
import org.apache.xml.utils.URI;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;

import java.util.HashSet;
import java.util.Set;

/**
 * XML-Security resolver that is used for resolving same-document URI like URI="#id".
 * It is desgined to only work with SOAPEnvelopes.
 * <p/>
 *
 * @author Davanum Srinivas (dims@yahoo.com).
 */
public class EnvelopeIdResolver extends ResourceResolverSpi {
    private static Log log =
            LogFactory.getLog(EnvelopeIdResolver.class.getName());
    private static Log tlog = LogFactory.getLog("org.apache.ws.security.TIME");

    private static EnvelopeIdResolver resolver = null;
    private WSSConfig wssConfig;

    private boolean doDebug = false;

    /**
     * Singleton instance of the resolver.
     * <p/>
     *
     * @return
     */
    public synchronized static ResourceResolverSpi getInstance(WSSConfig wssConfig) {
        // instance comparison, should be same instance most of the time
        // so no need for quals() here?
        if (resolver == null || resolver.wssConfig != wssConfig) {
            resolver = new EnvelopeIdResolver(wssConfig);
        }
        return resolver;
    }

    private EnvelopeIdResolver(WSSConfig wssConfig) {
        this.wssConfig = wssConfig;
    }

    /**
     * This is the workhorse method used to resolve resources.
     * <p/>
     *
     * @param uri
     * @param BaseURI
     * @return
     * @throws ResourceResolverException
     */
    public XMLSignatureInput engineResolve(Attr uri, String BaseURI)
            throws ResourceResolverException {

        doDebug = log.isDebugEnabled();

        long t0 = 0, t1 = 0;
        if (tlog.isDebugEnabled()) {
            t0 = System.currentTimeMillis();
        }

        String uriNodeValue = uri.getNodeValue();

        if (doDebug) {
            log.debug("enter engineResolve, look for: " + uriNodeValue);
        }

        Document doc = uri.getOwnerDocument();

        // Xalan fix for catching all namespaces
        XMLUtils.circumventBug2650(doc);

        /*
         * URI="#chapter1"
         * Identifies a node-set containing the element with ID attribute
         * value 'chapter1' of the XML resource containing the signature.
         * XML Signature (and its applications) modify this node-set to
         * include the element plus all descendents including namespaces and
         * attributes -- but not comments.
         */
         
        /*
         * First lookup the SOAP Body element (processed by default) and
         * check if it contains an Id and if it matches
         */
        String id = uriNodeValue.substring(1);
        SOAPConstants sc = WSSecurityUtil.getSOAPConstants(doc.getDocumentElement());
        Element selectedElem = WSSecurityUtil.findBodyElement(doc, sc);
        if (selectedElem == null) {
            throw new ResourceResolverException("generic.EmptyMessage",
                    new Object[]{"Body element not found"},
                    uri,
                    BaseURI);
        }
        String cId = selectedElem.getAttributeNS(wssConfig.getWsuNS(), "Id");

        /*
         * If Body Id match fails, look for a generic Id (without a namespace)
         * that matches the URI. If that lookup fails, try to get a namespace
         * qualified Id that matches the URI.
         */
        if (!id.equals(cId)) {
            cId = null;
            if ((selectedElem = WSSecurityUtil.getElementByWsuId(wssConfig, doc, uriNodeValue)) != null) {
                cId = selectedElem.getAttribute("Id");
            } else if ((selectedElem = WSSecurityUtil.getElementByGenId(doc, uriNodeValue)) != null) {
                cId = selectedElem.getAttribute("Id");
            }
            if (cId == null) {
                throw new ResourceResolverException("generic.EmptyMessage",
                        new Object[]{"Id not found"},
                        uri,
                        BaseURI);
            }
        }

        Set resultSet = dereferenceSameDocumentURI(selectedElem);
        XMLSignatureInput result = new XMLSignatureInput(resultSet);
        result.setMIMEType("text/xml");
        try {
            URI uriNew = new URI(new URI(BaseURI), uri.getNodeValue());
            result.setSourceURI(uriNew.toString());
        } catch (URI.MalformedURIException ex) {
            result.setSourceURI(BaseURI);
        }
        if (tlog.isDebugEnabled()) {
            t1 = System.currentTimeMillis();
            tlog.debug("engineResolve= " + (t1 - t0));
        }
        if (doDebug) {
            log.debug("exit engineResolve, result: " + result);
        }
        return result;
    }

    /**
     * This method helps the ResourceResolver to decide whether a
     * ResourceResolverSpi is able to perform the requested action.
     * <p/>
     *
     * @param uri
     * @param BaseURI
     * @return
     */
    public boolean engineCanResolve(Attr uri, String BaseURI) {
        if (uri == null) {
            return false;
        }
        String uriNodeValue = uri.getNodeValue();
        return uriNodeValue.startsWith("#");
    }

    /**
     * Dereferences a same-document URI fragment.
     *
     * @param node the node (document or element) referenced by the
     *             URI fragment. If null, returns an empty set.
     * @return a set of nodes (minus any comment nodes)
     */
    private Set dereferenceSameDocumentURI(Node node) {
        Set nodeSet = new HashSet();
        if (node != null) {
            nodeSetMinusCommentNodes(node, nodeSet, null);
        }
        return nodeSet;
    }

    /**
     * Recursively traverses the subtree, and returns an XPath-equivalent
     * node-set of all nodes traversed, excluding any comment nodes.
     *
     * @param node    the node to traverse
     * @param nodeSet the set of nodes traversed so far
     * @param the     previous sibling node
     */
    private void nodeSetMinusCommentNodes(Node node,
                                          Set nodeSet,
                                          Node prevSibling) {
        if (doDebug) {
            log.debug("Tag: "
                    + node.getNodeName()
                    + ", '"
                    + node.getNodeValue()
                    + "'");
        }
        switch (node.getNodeType()) {
            case Node.ELEMENT_NODE:
                NamedNodeMap attrs = node.getAttributes();
                if (attrs != null) {
                    for (int i = 0; i < attrs.getLength(); i++) {
                        if (doDebug) {
                            log.debug("Attr: "
                                    + attrs.item(i).getNodeName()
                                    + ", '"
                                    + attrs.item(i).getNodeValue()
                                    + "'");
                        }
                        nodeSet.add(attrs.item(i));
                    }
                }
                nodeSet.add(node);
                Node pSibling = null;
                for (Node child = node.getFirstChild();
                     child != null;
                     child = child.getNextSibling()) {
                    nodeSetMinusCommentNodes(child, nodeSet, pSibling);
                    pSibling = child;
                }
                break;
            case Node.TEXT_NODE:
            case Node.CDATA_SECTION_NODE:
                // emulate XPath which only returns the first node in
                // contiguous text/cdata nodes
                if (prevSibling != null
                        && (prevSibling.getNodeType() == Node.TEXT_NODE
                        || prevSibling.getNodeType()
                        == Node.CDATA_SECTION_NODE)) {
                    return;
                }
            case Node.PROCESSING_INSTRUCTION_NODE:
                nodeSet.add(node);
        }
    }
}
