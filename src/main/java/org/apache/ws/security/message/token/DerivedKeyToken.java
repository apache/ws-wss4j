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

package org.apache.ws.security.message.token;

import java.security.Principal;
import java.util.HashMap;
import java.util.Map;

import javax.xml.namespace.QName;

import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSDerivedKeyTokenPrincipal;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.conversation.ConversationConstants;
import org.apache.ws.security.conversation.ConversationException;
import org.apache.ws.security.conversation.dkalgo.AlgoFactory;
import org.apache.ws.security.conversation.dkalgo.DerivationAlgorithm;
import org.apache.ws.security.util.Base64;
import org.apache.ws.security.util.DOM2Writer;
import org.apache.ws.security.util.WSSecurityUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.Text;

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

    private static org.apache.commons.logging.Log log = 
        org.apache.commons.logging.LogFactory.getLog(DerivedKeyToken.class);

    // These are the elements that are used to create the SecurityContextToken
    protected Element element = null;
    protected Element elementSecurityTokenReference = null;
    protected Element elementProperties = null;
    protected Element elementGeneration = null;
    protected Element elementOffset = null;
    protected Element elementLength = null;
    protected Element elementLabel = null;
    protected Element elementNonce = null;
    
    private String ns;
    private boolean bspCompliant = true;
    
    /**
     * This will create an empty DerivedKeyToken
     *
     * @param doc The DOM document
     */
    public DerivedKeyToken(Document doc) throws ConversationException {
        this(ConversationConstants.DEFAULT_VERSION, doc);
    }

    /**
     * This will create an empty DerivedKeyToken
     *
     * @param doc The DOM document
     */
    public DerivedKeyToken(int version, Document doc) throws ConversationException {
        log.debug("DerivedKeyToken: created");
        
        ns = ConversationConstants.getWSCNs(version);
        element = 
            doc.createElementNS(ns, "wsc:" + ConversationConstants.DERIVED_KEY_TOKEN_LN);
        WSSecurityUtil.setNamespace(element, ns, ConversationConstants.WSC_PREFIX);
    }
    
    /**
     * This will create a DerivedKeyToken object with the given DerivedKeyToken element
     *
     * @param elem The DerivedKeyToken DOM element
     * @throws WSSecurityException If the element is not a derived key token
     */
    public DerivedKeyToken(Element elem) throws WSSecurityException {
        this(elem, true);
    }

    /**
     * This will create a DerivedKeyToken object with the given DerivedKeyToken element
     *
     * @param elem The DerivedKeyToken DOM element
     * @param bspCompliant whether the DerivedKeyToken processing complies with the BSP spec 
     * @throws WSSecurityException If the element is not a derived key token
     */
    public DerivedKeyToken(Element elem, boolean bspCompliant) throws WSSecurityException {
        log.debug("DerivedKeyToken: created : element constructor");
        element = elem;
        this.bspCompliant = bspCompliant;
        QName el = new QName(element.getNamespaceURI(), element.getLocalName());
        
        if (!(el.equals(ConversationConstants.DERIVED_KEY_TOKEN_QNAME_05_02) ||
            el.equals(ConversationConstants.DERIVED_KEY_TOKEN_QNAME_05_12))) {
            throw new WSSecurityException(
                WSSecurityException.INVALID_SECURITY_TOKEN
            );
        }
        elementSecurityTokenReference = 
            WSSecurityUtil.getDirectChildElement(
                element,
                ConversationConstants.SECURITY_TOKEN_REFERENCE_LN,
                WSConstants.WSSE_NS
            );
        
        ns = el.getNamespaceURI();
        
        elementProperties = 
            WSSecurityUtil.getDirectChildElement(
                element, ConversationConstants.PROPERTIES_LN, ns
            );
        elementGeneration = 
            WSSecurityUtil.getDirectChildElement(
                element, ConversationConstants.GENERATION_LN, ns
            );
        elementOffset = 
            WSSecurityUtil.getDirectChildElement(
                element, ConversationConstants.OFFSET_LN, ns
            );
        elementLength = 
            WSSecurityUtil.getDirectChildElement(
                element, ConversationConstants.LENGTH_LN, ns
            );
        elementLabel = 
            WSSecurityUtil.getDirectChildElement(
                element, ConversationConstants.LABEL_LN, ns
            );
        elementNonce = 
            WSSecurityUtil.getDirectChildElement(
                element, ConversationConstants.NONCE_LN, ns
            );
    }
    
    /**
     * Add the WSU Namespace to this DKT. The namespace is not added by default for
     * efficiency purposes.
     */
    public void addWSUNamespace() {
        WSSecurityUtil.setNamespace(element, WSConstants.WSU_NS, WSConstants.WSU_PREFIX);
    }

    /**
     * Sets the security token reference of the derived key token
     * This is the reference to the shared secret used in the conversation/context
     *
     * @param ref Security token reference
     */
    public void setSecurityTokenReference(SecurityTokenReference ref) {
        elementSecurityTokenReference = ref.getElement();
        WSSecurityUtil.prependChildElement(element, ref.getElement());
    }
    
    public void setSecurityTokenReference(Element elem) {
        elementSecurityTokenReference = elem;
        WSSecurityUtil.prependChildElement(element, elem);
    }
    
    /**
     * Returns the SecurityTokenReference of the derived key token
     *
     * @return the Security Token Reference of the derived key token
     * @throws WSSecurityException
     */
    public SecurityTokenReference getSecurityTokenReference() throws WSSecurityException {
        if (elementSecurityTokenReference != null) {
            return new SecurityTokenReference(elementSecurityTokenReference, bspCompliant);
        }
        return null;
    }
    
    /**
     * Returns the SecurityTokenReference element of the derived key token
     *
     * @return the Security Token Reference element of the derived key token
     */
    public Element getSecurityTokenReferenceElement() {
        return elementSecurityTokenReference;
    }
    
    /**
     * This adds a property into
     * /DerivedKeyToken/Properties
     *
     * @param propName  Name of the property
     * @param propValue Value of the property
     */
    private void addProperty(String propName, String propValue) {
        if (elementProperties == null) { //Create the properties element if it is not there
            elementProperties = 
                element.getOwnerDocument().createElementNS(
                    ns, "wsc:" + ConversationConstants.PROPERTIES_LN
                );
            element.appendChild(elementProperties);
        }
        Element tempElement = 
            element.getOwnerDocument().createElementNS(ns, "wsc:" + propName);
        tempElement.appendChild(element.getOwnerDocument().createTextNode(propValue));

        elementProperties.appendChild(tempElement);
    }

    /**
     * This is used to set the Name, Label and Nonce element values in the properties element
     * <b>At this point I'm not sure if these are the only properties that will appear in the
     * <code>Properties</code> element. There fore this method is provided
     * If this is not required feel free to remove this :D
     * </b>
     *
     * @param name  Value of the Properties/Name element
     * @param label Value of the Properties/Label element
     * @param nonce Value of the Properties/Nonce element
     */
    public void setProperties(String name, String label, String nonce) {
        Map<String, String> table = new HashMap<String, String>();
        table.put("Name", name);
        table.put("Label", label);
        table.put("Nonce", nonce);
        setProperties(table);
    }

    /**
     * If there are other types of properties other than Name, Label and Nonce
     * This is provided for extensibility purposes
     *
     * @param properties The properties and values in a Map
     */
    public void setProperties(Map<String, String> properties) {
        for (String key : properties.keySet()) {
            String propertyName = properties.get(key); //Get the property name
            //Check whether this property is already there
            //If so change the value
            Element node = 
                WSSecurityUtil.findElement(elementProperties, propertyName, ns);
            if (node != null) { //If the node is not null
                Text node1 = getFirstNode(node);
                node1.setData(properties.get(propertyName));
            } else {
                addProperty(propertyName, properties.get(propertyName));
            }
        }
    }

    public Map<String, String> getProperties() {
        if (elementProperties != null) {
            Map<String, String> table = new HashMap<String, String>();
            Node node = elementProperties.getFirstChild();
            while (node != null) {
                if (Node.ELEMENT_NODE == node.getNodeType()) {
                    Text text = getFirstNode((Element) node);
                    table.put(node.getNodeName(), text.getData());
                }
                node = node.getNextSibling();
            }
        }
        return null;
    }

    /**
     * Sets the length of the derived key
     *
     * @param length The length of the derived key as a long
     */
    public void setLength(int length) {
        elementLength = 
            element.getOwnerDocument().createElementNS(
                ns, "wsc:" + ConversationConstants.LENGTH_LN
            );
        elementLength.appendChild(
            element.getOwnerDocument().createTextNode(Long.toString(length))
        );
        element.appendChild(elementLength);
    }

    public int getLength() {
        if (elementLength != null) {
            return Integer.parseInt(getFirstNode(elementLength).getData());
        }
        return 32;
    }

    /**
     * Sets the offset
     *
     * @param offset The offset value as an integer
     */
    public void setOffset(int offset) throws ConversationException {
        //This element MUST NOT be used if the <Generation> element is specified
        if (elementGeneration == null) {
            elementOffset = 
                element.getOwnerDocument().createElementNS(
                    ns, "wsc:" + ConversationConstants.OFFSET_LN
                );
            elementOffset.appendChild(
                element.getOwnerDocument().createTextNode(Integer.toString(offset))
            );
            element.appendChild(elementOffset);
        } else {
            throw new ConversationException(
                "Offset cannot be set along with generation - generation is already set"
            );
        }

    }

    public int getOffset() {
        if (elementOffset != null) {
            return Integer.parseInt(getFirstNode(elementOffset).getData());
        }
        return 0;
    }

    /**
     * Sets the generation of the derived key
     *
     * @param generation generation value as an integer
     */
    public void setGeneration(int generation) throws ConversationException {
        //This element MUST NOT be used if the <Offset> element is specified
        if (elementOffset == null) {
            elementGeneration = 
                element.getOwnerDocument().createElementNS(
                    ns, "wsc:" + ConversationConstants.GENERATION_LN
                );
            elementGeneration.appendChild(
                element.getOwnerDocument().createTextNode(Integer.toString(generation))
            );
            element.appendChild(elementGeneration);
        } else {
            throw new ConversationException(
                "Generation cannot be set along with offset - Offset is already set"
            );
        }
    }

    public int getGeneration() {
        if (elementGeneration != null) {
            return Integer.parseInt(getFirstNode(elementGeneration).getData());
        }
        return -1;
    }

    /**
     * Sets the label of the derived key
     *
     * @param label Label value as a string
     */
    public void setLabel(String label) {
        elementLabel = 
            element.getOwnerDocument().createElementNS(
                ns, "wsc:" + ConversationConstants.LABEL_LN
            );
        elementLabel.appendChild(element.getOwnerDocument().createTextNode(label));
        element.appendChild(elementLabel);
    }

    /**
     * Sets the nonce value of the derived key
     *
     * @param nonce Nonce value as a string
     */
    public void setNonce(String nonce) {
        elementNonce = 
            element.getOwnerDocument().createElementNS(
                ns, "wsc:" + ConversationConstants.NONCE_LN
            );
        elementNonce.appendChild(element.getOwnerDocument().createTextNode(nonce));
        element.appendChild(elementNonce);
    }

    /**
     * Returns the label of the derived key token
     *
     * @return Label of the derived key token
     */
    public String getLabel() {
        if (elementLabel != null) {
            return getFirstNode(elementLabel).getData();
        }
        return null;
    }

    /**
     * Return the nonce of the derived key token
     *
     * @return Nonce of the derived key token
     */
    public String getNonce() {
        if (elementNonce != null) {
            return getFirstNode(elementNonce).getData();
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
        return (node != null && Node.TEXT_NODE == node.getNodeType()) ? (Text) node : null;
    }

    /**
     * Returns the dom element of this <code>SecurityContextToken</code> object.
     *
     * @return the DerivedKeyToken element
     */
    public Element getElement() {
        return element;
    }

    /**
     * Returns the string representation of the token.
     *
     * @return a XML string representation
     */
    public String toString() {
        return DOM2Writer.nodeToString((Node)element);
    }

    /**
     * Gets the id.
     *
     * @return the value of the <code>wsu:Id</code> attribute of this
     *         DerivedKeyToken
     */
    public String getID() {
        return element.getAttributeNS(WSConstants.WSU_NS, "Id");
    }

    /**
     * Set the id of this derived key token.
     *
     * @param id the value for the <code>wsu:Id</code> attribute of this
     *           DerivedKeyToken
     */
    public void setID(String id) {
        element.setAttributeNS(WSConstants.WSU_NS, WSConstants.WSU_PREFIX + ":Id", id);
    }

    /**
     * Gets the derivation algorithm
     *
     * @return the value of the <code>wsc:Algorithm</code> attribute of this
     *         DerivedKeyToken
     */
    public String getAlgorithm() {
        String algo = element.getAttributeNS(ns, "Algorithm");
        if (algo == null || algo.equals("")) {
            return ConversationConstants.DerivationAlgorithm.P_SHA_1;
        } else {
            return algo;
        }
    }
    
    /**
     * Create a WSDerivedKeyTokenPrincipal from this DerivedKeyToken object
     */
    public Principal createPrincipal() throws WSSecurityException {
        WSDerivedKeyTokenPrincipal principal = new WSDerivedKeyTokenPrincipal(getID());
        principal.setNonce(getNonce());
        principal.setLabel(getLabel());
        principal.setLength(getLength());
        principal.setOffset(getOffset());
        principal.setAlgorithm(getAlgorithm());
        
        String basetokenId = null;
        SecurityTokenReference securityTokenReference = getSecurityTokenReference();
        if (securityTokenReference.containsReference()) {
            basetokenId = securityTokenReference.getReference().getURI();
            if (basetokenId.charAt(0) == '#') {
                basetokenId = basetokenId.substring(1);
            }
        } else {
            // KeyIdentifier
            basetokenId = securityTokenReference.getKeyIdentifierValue();
        }
        principal.setBasetokenId(basetokenId);
        
        return principal;
    }

    /**
     * Set the derivation algorithm of this derived key token.
     *
     * @param algo the value for the <code>Algorithm</code> attribute of this
     *             DerivedKeyToken
     */
    public void setAlgorithm(String algo) {
        element.setAttributeNS(ns, "Algorithm", algo);
    }
    
    /**
     * Derive a key from this DerivedKeyToken instance
     * @param length
     * @param secret
     * @throws WSSecurityException
     */
    public byte[] deriveKey(int length, byte[] secret) throws WSSecurityException {
        try {
            DerivationAlgorithm algo = AlgoFactory.getInstance(getAlgorithm());
            byte[] labelBytes = null;
            String label = getLabel();
            if (label == null || label.length() == 0) {
                labelBytes = 
                    (ConversationConstants.DEFAULT_LABEL 
                        + ConversationConstants.DEFAULT_LABEL).getBytes("UTF-8");
            } else {
                labelBytes = label.getBytes("UTF-8");
            }
            
            byte[] nonce = Base64.decode(getNonce());
            byte[] seed = new byte[labelBytes.length + nonce.length];
            System.arraycopy(labelBytes, 0, seed, 0, labelBytes.length);
            System.arraycopy(nonce, 0, seed, labelBytes.length, nonce.length);
            
            if (length <= 0) {
                length = getLength();
            }
            return algo.createKey(secret, seed, getOffset(), length);
            
        } catch (Exception e) {
            throw new WSSecurityException(
                WSSecurityException.FAILURE, null, null, e
            );
        }
    }
    
    @Override
    public int hashCode() {
        int result = 17;
        String algorithm = getAlgorithm();
        if (algorithm != null) {
            result = 31 * result + algorithm.hashCode();
        }
        try {
            SecurityTokenReference tokenReference = getSecurityTokenReference();
            if (tokenReference != null) {
                result = 31 * result + tokenReference.hashCode();
            }
        } catch (WSSecurityException e) {
            log.error(e);
        }
        
        Map<String, String> properties = getProperties();
        if (properties != null) {
            result = 31 * result + properties.hashCode();
        }
        int generation = getGeneration();
        if (generation != -1) {
            result = 31 * result + generation;
        }
        int offset = getOffset();
        if (offset != -1) {
            result = 31 * result + offset;
        }
        int length = getLength();
        if (length != -1) {
            result = 31 * result + length;
        }
        String label = getLabel();
        if (label != null) {
            result = 31 * result + label.hashCode();
        }
        String nonce = getNonce();
        if (nonce != null) {
            result = 31 * result + nonce.hashCode();
        }
        
        return result;
    }
    
    @Override
    public boolean equals(Object object) {
        if (!(object instanceof DerivedKeyToken)) {
            return false;
        }
        DerivedKeyToken token = (DerivedKeyToken)object;
        if (!compare(getAlgorithm(), token.getAlgorithm())) {
            return false;
        }
        try {
            if (!getSecurityTokenReference().equals(token.getSecurityTokenReference())) {
                return false;
            }
        } catch (WSSecurityException e) {
            log.error(e);
            return false;
        }
        if (!compare(getProperties(), token.getProperties())) {
            return false;
        }
        if (getGeneration() != token.getGeneration()) {
            return false;
        }
        if (getOffset() != token.getOffset()) {
            return false;
        }
        if (getLength() != token.getLength()) {
            return false;
        }
        if (!compare(getLabel(), token.getLabel())) {
            return false;
        }
        if (!compare(getNonce(), token.getNonce())) {
            return false;
        }
        return true;
    }
    
    private boolean compare(String item1, String item2) {
        if (item1 == null && item2 != null) { 
            return false;
        } else if (item1 != null && !item1.equals(item2)) {
            return false;
        }
        return true;
    }
    
    private boolean compare(Map<String, String> item1, Map<String, String> item2) {
        if (item1 == null && item2 != null) { 
            return false;
        } else if (item1 != null && !item1.equals(item2)) {
            return false;
        }
        return true;
    }
}
