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

import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.conversation.ConversationConstants;
import org.apache.ws.security.message.token.SecurityTokenReference;
import org.apache.ws.security.util.DOM2Writer;
import org.apache.ws.security.util.WSSecurityUtil;
import org.apache.xml.security.encryption.EncryptedKey;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.Text;

import javax.xml.namespace.QName;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.TimeZone;

/**
 * Class SecurityContextToken
 */
public class SecurityContextToken {

    /**
     * Field TOKEN
     */
    public static final QName TOKEN =
            new QName(WSConstants.WSSE_NS,
                    ConversationConstants.SECURITY_CONTEXT_TOKEN_LN);

    // These are the elements that are used to create the SecurityContextToken

    /**
     * Field element
     */
    protected Element element = null;

    /**
     * Field elementIdentifier
     */
    protected Element elementIdentifier = null;

    /**
     * Field elementCreated
     */
    protected Element elementCreated = null;

    /**
     * Field elementExpires
     */
    protected Element elementExpires = null;

    /**
     * Field elementKeys
     */
    protected Element elementKeys = null;

    /**
     * Field elementEncryptedKey
     */
    protected Element elementEncryptedKey = null;

    /**
     * Field elementSecurityTokenReference
     */
    protected Element elementSecurityTokenReference = null;

    /**
     * The time difference between the created time and the expiration time
     */
    protected int timeout = 12;

    /**
     * This constructor creates a security context token and adds the identifier
     * 
     * @param doc The DOM Document
     */
    public SecurityContextToken(Document doc) {
        this.element = doc.createElementNS(WSConstants.WSSE_NS,
                "wsse:" + ConversationConstants.SECURITY_CONTEXT_TOKEN_LN);
        WSSecurityUtil.setNamespace(this.element, WSConstants.WSSE_NS,
                WSConstants.WSSE_PREFIX);
        this.addIdentifier(doc);    // SEt the uuid
        if (elementCreated == null) {
            addCreatedAndExpires(doc);
        }
    }

    /**
     * Constructor to create the SCT given the identifier.
     * 
     * @param doc        
     * @param identifier 
     */
    public SecurityContextToken(Document doc, String identifier) {
        this.element = doc.createElementNS(WSConstants.WSSE_NS,
                "wsse:" + ConversationConstants.SECURITY_CONTEXT_TOKEN_LN);
        WSSecurityUtil.setNamespace(this.element, WSConstants.WSSE_NS,
                WSConstants.WSSE_PREFIX);
        this.elementIdentifier = doc.createElementNS(WSConstants.WSSE_NS,
                "wsse:" + ConversationConstants.IDENTIFIER_LN);
        this.element.appendChild(this.elementIdentifier);
        this.elementIdentifier.appendChild(doc.createTextNode(identifier));
    }

    /**
     * Constructor to set a custom timeout
     * 
     * @param doc     The DOM Document
     * @param timeout Difference between the creating time and expiration time
     */
    public SecurityContextToken(Document doc, int timeout) {
        // Call to overloaded constructor must vbe the first line
        // But here the timeout has to be set earlier as it is used in addCreatedAndExpires();
        this.element = doc.createElementNS(WSConstants.WSSE_NS,
                "wsse:" + ConversationConstants.SECURITY_CONTEXT_TOKEN_LN);
        WSSecurityUtil.setNamespace(this.element, WSConstants.WSSE_NS,
                WSConstants.WSSE_PREFIX);
        this.addIdentifier(doc);    // Set the uuid
        this.setTimeout(timeout);    // Change the default value of timeout to the given value
        if (elementCreated == null) {
            addCreatedAndExpires(doc);
        }
    }

    /**
     * This will generate the Identifier element and generate and set the uuid.s
     * <b>The generation of the UUID is NOT coded </b>
     * 
     * @param doc The DOM Document
     */
    private void addIdentifier(Document doc) {
        this.elementIdentifier = doc.createElementNS(WSConstants.WSSE_NS,
                "wsse:" + ConversationConstants.IDENTIFIER_LN);
        WSSecurityUtil.setNamespace(this.elementIdentifier,
                WSConstants.WSSE_NS,
                WSConstants.WSSE_PREFIX);
        String uuid;

        // Creation of the uuid :START

        /** @todo */
        uuid = "uuid:secureZone";

        // Creation of the uuid :END
        this.elementIdentifier.appendChild(doc.createTextNode(uuid));
        element.appendChild(elementIdentifier);
    }

    /**
     * This is used to create a SecurityContestToken using a DOM Element
     * 
     * @param elem The DOM element: The security context token
     * @throws WSSecurityException If the element passed in in not a security context token
     */
    public SecurityContextToken(Element elem) throws WSSecurityException {
        this.element = elem;
        QName el = new QName(this.element.getNamespaceURI(),
                this.element.getLocalName());
        if (!el.equals(TOKEN)) {    // If the element is not a security context token
            throw new WSSecurityException(WSSecurityException.INVALID_SECURITY_TOKEN, "badTokenType00",
                    new Object[]{el});
        }
        this.elementIdentifier = (Element) WSSecurityUtil.getDirectChild(element, ConversationConstants.IDENTIFIER_LN, WSConstants.WSSE_NS);
        this.elementCreated =
                (Element) WSSecurityUtil.getDirectChild(element,
                        WSConstants.CREATED_LN,
                        WSConstants.WSU_NS);
        this.elementExpires =
                (Element) WSSecurityUtil.getDirectChild(element,
                        WSConstants.EXPIRES_LN,
                        WSConstants.WSU_NS);

        // this.elementKeys = (Element) WSSecurityUtil.getDirectChild(element,
        // ConversationConstants.KEYS_LN, WSConstants.WSSE_NS);
        // this.elementEncryptedKey = (Element) WSSecurityUtil.getDirectChild(
        // elementKeys, WSConstants.ENC_KEY_LN, WSConstants.WSSE_NS);
        // this.elementSecurityTokenReference = (Element) WSSecurityUtil.
        // getDirectChild(elementKeys, "SecurityTokenReference",
        // WSConstants.WSSE_NS);
        System.out.println("*\n*\n**\n*\n*\n*\n*\n*****");

        // if (this.elementIdentifier == null) {
        // There can't be an SCT without an identifier
        // we still don't have pur own exception class with the properset of error states
        // therefore WSSecurityException is trown
        // throw new WSSecurityException(WSSecurityException.INVALID_SECURITY_TOKEN,
        // "badTokenType01", new Object[] {el});
        // }
    }

    /**
     * This sets the time difference between the created time and the expiration
     * time in hours
     * The default value is 12 hours
     * 
     * @param timeout the number of hours
     */
    private void setTimeout(int timeout) {
        this.timeout = timeout;
    }

    /**
     * Returns the timeout value
     * This is the difference between the created time and the expired time
     * 
     * @return The timeout in hours
     */
    public int getTimeout() {
        return this.timeout;
    }

    /**
     * Set the identifier.
     * 
     * @param name sets a text node containing the identifier into
     *             the identifier element.
     * @param doc  
     * @param uuid 
     */
    public void setIdentifier(Document doc, String uuid) {
        Text node = getFirstNode(this.elementIdentifier);
        node.setData(uuid);
    }

    /**
     * Creates and adds a Created element to this UsernameToken
     * 
     * @param doc The DOM Document
     */
    public void addCreatedAndExpires(Document doc) {
        SimpleDateFormat zulu =
                new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
        zulu.setTimeZone(TimeZone.getTimeZone("GMT"));
        Calendar rightNow = Calendar.getInstance();
        this.elementCreated = doc.createElementNS(WSConstants.WSU_NS,
                "wsu:"
                + WSConstants.CREATED_LN);
        WSSecurityUtil.setNamespace(this.elementCreated, WSConstants.WSU_NS,
                WSConstants.WSU_PREFIX);
        this.elementExpires =
                doc.createElementNS(WSConstants.WSU_NS,
                        "wsu:" + ConversationConstants.EXPIRES_LN);
        WSSecurityUtil.setNamespace(this.elementCreated, WSConstants.WSU_NS,
                WSConstants.WSU_PREFIX);
        this.elementCreated.appendChild(doc.createTextNode(zulu.format(rightNow.getTime())));
        element.appendChild(elementCreated);
        String expTimeZone = "GMT+" + this.timeout
                + ":00";    // The expiration time
        zulu.setTimeZone(TimeZone.getTimeZone(expTimeZone));
        this.elementExpires.appendChild(doc.createTextNode(zulu.format(rightNow.getTime())));
        element.appendChild(elementExpires);
    }

    /**
     * Set the encrypted key.
     * 
     * @param doc          
     * @param encryptedKey 
     */
    public void setEncryptedKey(Document doc, EncryptedKey encryptedKey) {
        // If there is no keys element then create it
        if (this.elementKeys == null) {
            this.elementKeys = doc.createElementNS(WSConstants.WSSE_NS,
                    "wsse:Keys");
            this.element.appendChild(this.elementKeys);
        }

        /** @todo : Still not sure how to do this */
    }

    /**
     * Method setSecuityTokenReference
     * 
     * @param doc 
     * @param ref 
     */
    public void setSecuityTokenReference(Document doc,
                                         SecurityTokenReference ref) {
        // If there is no keys element then create it
        if (this.elementKeys == null) {
            this.elementKeys =
                    doc.createElementNS(WSConstants.WSSE_NS,
                            "wsse:" + ConversationConstants.KEYS_LN);
            WSSecurityUtil.setNamespace(this.elementKeys, WSConstants.WSSE_NS,
                    WSConstants.WSSE_PREFIX);
            this.element.appendChild(this.elementKeys);
        }
        WSSecurityUtil.appendChildElement(doc, this.elementKeys,
                ref.getElement());
    }

    /**
     * Get the created timestamp.
     * 
     * @return the data from the created time element.
     */
    public String getCreated() {
        if (this.elementCreated != null) {
            return getFirstNode(this.elementCreated).getData();
        }
        return null;
    }

    /**
     * Get the identifier.
     * 
     * @return the data from the identifier element.
     */
    public String getIdentifier() {
        if (this.elementIdentifier != null) {
            return getFirstNode(this.elementIdentifier).getData();
        }
        return null;
    }

    /**
     * Get the expiration timestamp.
     * 
     * @return the data from the created time element.
     */
    public String getExpires() {
        if (this.elementExpires != null) {
            System.out.println("Date is ..............:: "
                    + this.elementExpires.getChildNodes().item(0).getNodeValue());
            return this.elementExpires.getChildNodes().item(0).getNodeValue();
        }
        return null;
    }

    /**
     * Set the created timestamp.
     * 
     * @param created sets a text node containing the created time data into
     *                the created time element.
     */
    public void setCreated(String created) {
        Text node = getFirstNode(this.elementCreated);
        node.setData(created);
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
        return ((node != null) && (node instanceof Text))
                ? (Text) node
                : null;
    }

    /**
     * Returns the dom element of this <code>SecurityContextToken</code> object.
     * 
     * @return the <code>wsse:UsernameToken</code> element
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
     *         SecurityContextToken
     */
    public String getID() {
        return this.element.getAttributeNS(WSConstants.WSU_NS, "Id");
    }

    /**
     * Set the id of this username token.
     * 
     * @param id the value for the <code>wsu:Id</code> attribute of this
     *           SecurityContextToken
     */
    public void setID(String id) {
        String prefix = WSSecurityUtil.setNamespace(this.element,
                WSConstants.WSU_NS,
                WSConstants.WSU_PREFIX);
        this.element.setAttributeNS(WSConstants.WSU_NS, prefix + ":Id", id);
    }
}
