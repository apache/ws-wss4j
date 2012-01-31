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

import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.conversation.ConversationConstants;
import org.apache.ws.security.conversation.ConversationException;
import org.apache.ws.security.util.DOM2Writer;
import org.apache.ws.security.util.UUIDGenerator;
import org.apache.ws.security.util.WSSecurityUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.Text;

import javax.xml.namespace.QName;

/**
 * @author Ruchith Fernando
 * @version 1.0
 */
public class SecurityContextToken {

    /**
     * Security context token element
     */
    protected Element element = null;

    /**
     * Identifier element
     */
    protected Element elementIdentifier = null;
    
    private WSSConfig wssConfig = WSSConfig.getNewInstance();
    
    private String tokenType = WSConstants.WSC_SCT;
    
    /**
     * Constructor to create the SCT
     *
     * @param doc
     */
    public SecurityContextToken(Document doc) throws ConversationException {
        this(ConversationConstants.DEFAULT_VERSION, doc);
    }

    /**
     * Constructor to create the SCT with a given uuid
     *
     * @param doc
     */
    public SecurityContextToken(Document doc, String uuid) throws ConversationException {
        this(ConversationConstants.DEFAULT_VERSION, doc, uuid);
    }

    /**
     * Constructor to create the SCT
     *
     * @param doc
     */
    public SecurityContextToken(int version, Document doc) throws ConversationException {

        String ns = ConversationConstants.getWSCNs(version);
        
        element = 
            doc.createElementNS(ns, "wsc:" + ConversationConstants.SECURITY_CONTEXT_TOKEN_LN);

        WSSecurityUtil.setNamespace(element, ns, ConversationConstants.WSC_PREFIX);

        elementIdentifier = 
            doc.createElementNS(ns, "wsc:" + ConversationConstants.IDENTIFIER_LN);

        element.appendChild(elementIdentifier);

        String uuid = "uuid:" + UUIDGenerator.getUUID();
        
        elementIdentifier.appendChild(doc.createTextNode(uuid));
        
        setID(wssConfig.getIdAllocator().createSecureId("sctId-", element));
    }

    /**
     * Constructor to create the SCT with a given uuid
     *
     * @param doc
     */
    public SecurityContextToken(int version, Document doc, String uuid) throws ConversationException {

        String ns = ConversationConstants.getWSCNs(version);
        
        element = 
            doc.createElementNS(ns, "wsc:" + ConversationConstants.SECURITY_CONTEXT_TOKEN_LN);

        WSSecurityUtil.setNamespace(element, ns, ConversationConstants.WSC_PREFIX);

        elementIdentifier = 
            doc.createElementNS(ns, "wsc:" + ConversationConstants.IDENTIFIER_LN);

        element.appendChild(elementIdentifier);

        elementIdentifier.appendChild(doc.createTextNode(uuid));
        
        if (version == ConversationConstants.VERSION_05_02) {
            tokenType = WSConstants.WSC_SCT;
        } else {
            tokenType = WSConstants.WSC_SCT_05_12;
        }
    }

    
    /**
     * This is used to create a SecurityContextToken using a DOM Element
     *
     * @param elem The DOM element: The security context token
     * @throws WSSecurityException If the element passed in in not a security context token
     */
    public SecurityContextToken(Element elem) throws WSSecurityException {
        element = elem;
        QName el = new QName(element.getNamespaceURI(), element.getLocalName());

        // If the element is not a security context token, throw an exception
        if (el.equals(ConversationConstants.SECURITY_CTX_TOKEN_QNAME_05_02)) {
            tokenType = WSConstants.WSC_SCT;
        } else if (el.equals(ConversationConstants.SECURITY_CTX_TOKEN_QNAME_05_12)) {
            tokenType = WSConstants.WSC_SCT_05_12;
        } else {
            throw new WSSecurityException(WSSecurityException.INVALID_SECURITY_TOKEN);
        }

        elementIdentifier = 
            WSSecurityUtil.getDirectChildElement(
                element, 
                ConversationConstants.IDENTIFIER_LN,
                el.getNamespaceURI()
            );
    }
    
    /**
     * Add the WSU Namespace to this SCT. The namespace is not added by default for
     * efficiency purposes.
     */
    public void addWSUNamespace() {
        WSSecurityUtil.setNamespace(element, WSConstants.WSU_NS, WSConstants.WSU_PREFIX);
    }

    /**
     * Set the identifier.
     */
    public void setIdentifier(String uuid) {
        Text node = getFirstNode(elementIdentifier);
        node.setData(uuid);
    }

    /**
     * Get the identifier.
     *
     * @return the data from the identifier element.
     */
    public String getIdentifier() {
        if (elementIdentifier != null) {
            return getFirstNode(elementIdentifier).getData();
        }
        return null;
    }
    
    /**
     * Get the WS-Trust tokenType String associated with this token
     */
    public String getTokenType() {
        return tokenType;
    }

    public void setElement(Element elem) {
        element.appendChild(elem);
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
     * @return the <code>wsse:SecurityContextToken</code> element
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
     *         SecurityContextToken
     */
    public String getID() {
        return element.getAttributeNS(WSConstants.WSU_NS, "Id");
    }

    /**
     * Set the id of this security context token.
     *
     * @param id the value for the <code>wsu:Id</code> attribute of this
     *           SecurityContextToken
     */
    public void setID(String id) {
        element.setAttributeNS(WSConstants.WSU_NS, WSConstants.WSU_PREFIX + ":Id", id);
    }
    
    @Override
    public int hashCode() {
        int result = 17;
        String identifier = getIdentifier();
        if (identifier != null) {
            result = 31 * result + identifier.hashCode();
        }
        return result;
    }
    
    @Override
    public boolean equals(Object object) {
        if (!(object instanceof SecurityContextToken)) {
            return false;
        }
        SecurityContextToken securityToken = (SecurityContextToken)object;
        if (!compare(getIdentifier(), securityToken.getIdentifier())) {
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

}
