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
package org.apache.ws.security.conversation.message.token;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.conversation.ConversationConstants;
import org.apache.ws.security.conversation.ConversationException;
import org.apache.ws.security.conversation.dkAlgo.DerivationAlgorithm;
import org.apache.ws.security.message.token.SecurityTokenReference;
import org.apache.ws.security.util.DOM2Writer;
import org.apache.ws.security.util.WSSecurityUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.w3c.dom.Text;

import javax.xml.namespace.QName;
import java.util.Enumeration;
import java.util.Hashtable;

/**
 <DerivedKeyToken wsu:Id="..." wsc:Algorithm="...">
 <SecurityTokenReference>...</SecurityTokenReference>
 <Properties>...</Properties>
 <Generation>...</Generation>
 <Offset>...</Offset>
 <Length>...</Length>
 <Label>...</Label>
 <Nonce>...</Nonce>
 </DerivedKeyToken>
 */

/**
 * @author Ruchith Fernando
 * @version 1.0
 */
public class DerivedKeyToken {

    private Log log = LogFactory.getLog(DerivedKeyToken.class.getName());

    public static final QName TOKEN = new QName(ConversationConstants.WSC_NS,
            ConversationConstants.
            DERIVED_KEY_TOKEN_LN);

    //These are the elements that are used to create the SecurityContextToken
    protected Element element = null;
    protected Element elementSecurityTokenReference = null;
    protected Element elementProperties = null;
    protected Element elementGeneration = null;
    protected Element elementOffset = null;
    protected Element elementLength = null;
    protected Element elementLabel = null;
    protected Element elementNonce = null;

    /**
     * This will create an empty DerivedKeyToken
     *
     * @param doc THe DOM document
     */
    public DerivedKeyToken(Document doc) {
        log.debug("DerivedKeyToken: created");
        this.element = doc.createElementNS(ConversationConstants.WSC_NS,
                "wsc:" +
                ConversationConstants.
                DERIVED_KEY_TOKEN_LN);
        WSSecurityUtil.setNamespace(this.element, ConversationConstants.WSC_NS,
                ConversationConstants.WSC_PREFIX);
    }

    /**
     * This will create a DerivedKeyToken object with the given DErivedKeyToken element
     *
     * @param elem The DErivedKeyToken DOM element
     * @throws WSSecurityException If the element is not a derived key token
     */
    public DerivedKeyToken(Element elem) throws WSSecurityException {
        log.debug("DerivedKeyToken: created : element constructor");
        this.element = elem;
        QName el = new QName(this.element.getNamespaceURI(),
                this.element.getLocalName());
        if (!el.equals(TOKEN)) {
            throw new WSSecurityException(WSSecurityException.INVALID_SECURITY_TOKEN,
                    "badTokenType00", new Object[]{el});
        }
        this.elementSecurityTokenReference = (Element) WSSecurityUtil.
                getDirectChild(this.element,
                        ConversationConstants.SECURITY_TOKEN_REFERENCE_LN,
                        WSConstants.WSSE_NS);
        this.elementProperties = (Element) WSSecurityUtil.getDirectChild(this.
                element, ConversationConstants.PROPERTIES_LN,
                ConversationConstants.WSC_NS);
        this.elementGeneration = (Element) WSSecurityUtil.getDirectChild(this.
                element, ConversationConstants.GENERATION_LN,
                ConversationConstants.WSC_NS);
        this.elementOffset = (Element) WSSecurityUtil.getDirectChild(this.element,
                ConversationConstants.OFFSET_LN, ConversationConstants.WSC_NS);
        this.elementLength = (Element) WSSecurityUtil.getDirectChild(this.element,
                ConversationConstants.LENGTH_LN, ConversationConstants.WSC_NS);
        this.elementLabel = (Element) WSSecurityUtil.getDirectChild(this.element,
                ConversationConstants.LABEL_LN, ConversationConstants.WSC_NS);
        this.elementNonce = (Element) WSSecurityUtil.getDirectChild(this.element,
                ConversationConstants.NONCE_LN, ConversationConstants.WSC_NS);
    }

    /**
     * Sets the security token reference of the derived key token
     * This is the reference to the shared secret used in the conversation/context
     *
     * @param doc The DOM document
     * @param ref Security token reference
     */
    public void setSecuityTokenReference(Document doc, SecurityTokenReference ref) {
        WSSecurityUtil.appendChildElement(doc, this.element, ref.getElement());
    }

    /**
     * Returns the SecurityTokenReference of the derived key token
     *
     * @return
     * @throws WSSecurityException
     */
    public SecurityTokenReference getSecuityTokenReference() throws
            WSSecurityException {
        if (this.elementSecurityTokenReference != null) {
            return new SecurityTokenReference(WSSConfig.getDefaultWSConfig(), this.elementSecurityTokenReference);
        }
        return null;
    }

    //Write the getter for security token reference

    /**
     * This adds a property into
     * /DerivedKeyToken/Properties
     *
     * @param doc       The DOM document
     * @param propName  Name of the property
     * @param propValue Value of the property
     */
    private void addProperty(Document doc, String propName, String propValue) {
        if (this.elementProperties == null) { //Create the properties element if it is not there
            this.elementProperties = doc.createElementNS(ConversationConstants.WSC_NS,
                    "wsc:" +
                    ConversationConstants.PROPERTIES_LN);
            WSSecurityUtil.setNamespace(this.elementProperties,
                    ConversationConstants.WSC_NS,
                    WSConstants.WSSE_PREFIX);
            this.element.appendChild(this.elementProperties);
        }
        Element tempElement = doc.createElementNS(ConversationConstants.WSC_NS,
                "wsc:" + propName);
        tempElement.appendChild(doc.createTextNode(propValue));

        this.elementProperties.appendChild(tempElement);
    }

    /**
     * This is used to set the Name, Label and Nonce element values in the properties element
     * <b>At this point I'm not sure if these are the only properties that will appear in the
     * <code>Properties</code> element. There fore this method is provided
     * If this is not required feel free to remove this :D
     * </b>
     *
     * @param doc   The DOM document
     * @param name  Value of the Properties/Name element
     * @param label Value of the Properties/Label element
     * @param nonce Value of the Properties/Nonce element
     */
    public void setProperties(Document doc, String name, String label,
                              String nonce) {
        Hashtable table = new Hashtable(3);
        table.put("Name", name);
        table.put("Label", label);
        table.put("Nonce", nonce);
        this.setProperties(doc, table);
    }

    /**
     * If there are other types of properties other than Name, Label and Nonce
     * This is provided for extensibility purposes
     *
     * @param properties The properties and values in a hashtable
     */
    public void setProperties(Document doc, Hashtable properties) {
        Enumeration keys = properties.keys();
        while (keys.hasMoreElements()) {
            String propertyName = (String) keys.nextElement(); //Get the property name
            //Check whether this property is already there
            //If so change the value
            Node node = WSSecurityUtil.findElement(this.elementProperties,
                    propertyName,
                    ConversationConstants.WSC_NS);
            if (node != null && node instanceof Element) { //If the node is not null
                Text node1 = getFirstNode((Element) node);
                node1.setData((String) properties.get(propertyName));
            } else {
                this.addProperty(doc, propertyName,
                        (String) properties.get(propertyName));
            }
        }
    }

    public Hashtable getProperties() {
        if (this.elementProperties != null) {
            Hashtable table = new Hashtable();
            NodeList nodes = this.elementProperties.getChildNodes();
            for (int i = 0; i < nodes.getLength(); i++) {
                Node tempNode = nodes.item(i);
                if (tempNode instanceof Element) {
                    Text text = this.getFirstNode((Element) tempNode);
                    table.put(tempNode.getNodeName(), text.getData());
                }
            }

        }
        return null;
    }

    /**
     * Sets the length of the derived key
     *
     * @param doc    The DOM document
     * @param length The length of the derived key as a long
     */
    public void setLength(Document doc, long length) {
        this.elementLength = doc.createElementNS(ConversationConstants.WSC_NS,
                "wsc:" +
                ConversationConstants.LENGTH_LN);
        WSSecurityUtil.setNamespace(this.elementLength,
                ConversationConstants.WSC_NS,
                ConversationConstants.WSC_PREFIX);
        this.elementLength.appendChild(doc.createTextNode(Long.toString(length)));
        this.element.appendChild(this.elementLength);
    }

    public long getLength() {
        if (this.elementLength != null) {
            return Long.parseLong(getFirstNode(this.elementLength).getData());
        }
        return -1;
    }

    /**
     * Sets the offset
     *
     * @param doc    The DOM document
     * @param offset The offset value as an integer
     */
    public void setOffset(Document doc, int offset) throws ConversationException {
        //This element MUST NOT be used if the <Generation> element is specified
        if (this.elementGeneration == null) {
            this.elementOffset = doc.createElementNS(ConversationConstants.WSC_NS,
                    "wsc:" +
                    ConversationConstants.OFFSET_LN);
            WSSecurityUtil.setNamespace(this.elementOffset,
                    ConversationConstants.WSC_NS,
                    ConversationConstants.WSC_PREFIX);
            this.elementOffset.appendChild(doc.createTextNode(Integer.toString(offset)));
            this.element.appendChild(this.elementOffset);
        } else {
            throw new ConversationException("Offset cannot be set along with generation - generation is already set");
        }

    }

    public int getOffset() {
        if (this.elementOffset != null) {
            return Integer.parseInt(getFirstNode(this.elementOffset).getData());
        }
        return -1;
    }

    /**
     * Sets the generation of the derived key
     *
     * @param doc        The DOM document
     * @param generation generation value as an integer
     */
    public void setGeneration(Document doc, int generation) throws
            ConversationException {
        //This element MUST NOT be used if the <Offset> element is specified
        if (this.elementOffset == null) {
            this.elementGeneration = doc.createElementNS(ConversationConstants.WSC_NS,
                    "wsc:" + ConversationConstants.GENERATION_LN);
            WSSecurityUtil.setNamespace(this.elementGeneration,
                    ConversationConstants.WSC_NS,
                    ConversationConstants.WSC_PREFIX);
            this.elementGeneration.appendChild(doc.createTextNode(Integer.toString(generation)));
            this.element.appendChild(this.elementGeneration);
        } else {
            throw new ConversationException("Generatation cannot be set along with offset - Offset is already set");
        }
    }

    public int getGeneration() {
        if (this.elementGeneration != null) {
            return Integer.parseInt(getFirstNode(this.elementGeneration).getData());
        }
        return -1;
    }

    /**
     * Sets the label of the derived key
     *
     * @param doc   The DOM document
     * @param label Label value as a string
     */
    public void setLabel(Document doc, String label) {
        this.elementLabel = doc.createElementNS(ConversationConstants.WSC_NS,
                "wsc:" +
                ConversationConstants.LABEL_LN);
        WSSecurityUtil.setNamespace(this.elementLabel, ConversationConstants.WSC_NS,
                ConversationConstants.WSC_PREFIX);
        this.elementLabel.appendChild(doc.createTextNode(label));
        this.element.appendChild(this.elementLabel);
    }

    /**
     * Sets the nonce value of the derived key
     *
     * @param doc   The DOM document
     * @param nonce Nonce value as a string
     */
    public void setNonce(Document doc, String nonce) {
        this.elementNonce = doc.createElementNS(ConversationConstants.WSC_NS,
                "wsc:" +
                ConversationConstants.NONCE_LN);
        WSSecurityUtil.setNamespace(this.elementNonce, ConversationConstants.WSC_NS,
                ConversationConstants.WSC_PREFIX);
        this.elementNonce.appendChild(doc.createTextNode(nonce));
        this.element.appendChild(this.elementNonce);

    }

    /**
     * Returns the label of the derived key token
     *
     * @return Label of the derived key token
     */
    public String getLabel() {
        if (this.elementLabel != null) {
            return getFirstNode(this.elementLabel).getData();
        }
        return null;
    }

    /**
     * Return the nonce of the derived key token
     *
     * @return Nonce of the derived key token
     */
    public String getNonce() {
        if (this.elementNonce != null) {
            return getFirstNode(this.elementNonce).getData();
        }
        return null;
    }

    /**
     * Returns the first text node of an element.
     *
     * @param e the element to get the node from
     * @return the first text node or <code>null</code> if node
     *         is null or is not a text node
     */
    private Text getFirstNode(Element e) {
        Node node = e.getFirstChild();
        return ((node != null) && node instanceof Text) ? (Text) node : null;
    }

    /**
     * Returns the dom element of this <code>SecurityContextToken</code> object.
     *
     * @return the DerivedKeyToken element
     */
    public Element getElement() {
        return this.element;
    }

    /**
     * Returns the string representation of the token.
     *
     * @return a XML string representation
     */
    public String toString() {
        return DOM2Writer.nodeToString((Node) this.element);
    }

    /**
     * Gets the id.
     *
     * @return the value of the <code>wsu:Id</code> attribute of this
     *         DerivedKeyToken
     */
    public String getID() {
        return this.element.getAttributeNS(WSConstants.WSU_NS, "Id");
    }

    /**
     * Set the id of this derived key token.
     *
     * @param id the value for the <code>wsu:Id</code> attribute of this
     *           DerivgedKeyToken
     */
    public void setID(String id) {
        String prefix = WSSecurityUtil.setNamespace(this.element,
                WSConstants.WSU_NS,
                WSConstants.WSU_PREFIX);
        this.element.setAttributeNS(WSConstants.WSU_NS, prefix + ":Id", id);
    }

    /**
     * Gets the derivattion algorithm
     *
     * @return the value of the <code>wsc:Algorithm</code> attribute of this
     *         DerivedKeyToken
     */
    public String getAlgorithm() {
        String algo = this.element.getAttributeNS(ConversationConstants.WSC_NS,
                "Algorithm");
        if (algo == null || algo.equals("")) {
            return DerivationAlgorithm.P_SHA_1;
        } else {
            return algo;
        }
    }

    /**
     * Set the derivattion algorithm of this derived key token.
     *
     * @param derivattion algorithm the value for the <code>wsu:Algorithm</code> attribute of this
     *                    DerivgedKeyToken
     */
    public void setAlgorithm(String algo) {
        String prefix = WSSecurityUtil.setNamespace(this.element,
                ConversationConstants.WSC_NS,
                ConversationConstants.
                WSC_PREFIX);
        this.element.setAttributeNS(ConversationConstants.WSC_NS,
                prefix + ":Algorithm", algo);
    }

}