package org.apache.ws.security.message.token;

import org.apache.ws.security.WSConstants;
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
        
        this.element = doc.createElementNS(ns,
                "wsc:" + ConversationConstants.SECURITY_CONTEXT_TOKEN_LN);

        WSSecurityUtil.setNamespace(this.element,ns,
                ConversationConstants.WSC_PREFIX);

        this.elementIdentifier = doc.createElementNS(ns,
                "wsc:" + ConversationConstants.IDENTIFIER_LN);

        this.element.appendChild(this.elementIdentifier);

        String uuid = UUIDGenerator.getUUID();
        
        this.elementIdentifier.appendChild(doc.createTextNode(uuid));
        
        this.setID("sctId-" + this.element.hashCode());
    }

    /**
     * Constructor to create the SCT with a given uuid
     *
     * @param doc
     */
    public SecurityContextToken(int version, Document doc, String uuid) throws ConversationException {

        String ns = ConversationConstants.getWSCNs(version);
        
        this.element = doc.createElementNS(ns,
                "wsc:" + ConversationConstants.SECURITY_CONTEXT_TOKEN_LN);

        WSSecurityUtil.setNamespace(this.element, ns,
                ConversationConstants.WSC_PREFIX);

        this.elementIdentifier = doc.createElementNS(ns,
                "wsc:" + ConversationConstants.IDENTIFIER_LN);

        this.element.appendChild(this.elementIdentifier);

        this.elementIdentifier.appendChild(doc.createTextNode(uuid));
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

        if (!el.equals(new QName(ConversationConstants.WSC_NS_05_02, ConversationConstants.SECURITY_CONTEXT_TOKEN_LN)) &&
                !el.equals(new QName(ConversationConstants.WSC_NS_05_12, ConversationConstants.SECURITY_CONTEXT_TOKEN_LN))) {    // If the element is not a security context token
            throw new WSSecurityException(WSSecurityException.INVALID_SECURITY_TOKEN, "badTokenType00",
                    new Object[]{el});
        }

        this.elementIdentifier = (Element) WSSecurityUtil.getDirectChild(
                element, ConversationConstants.IDENTIFIER_LN, el
                        .getNamespaceURI());
    }

    /**
     * Set the identifier.
     *
     * @param name sets a text node containing the identifier into
     *             the identifier element.
     */
    public void setIdentifier(Document doc, String uuid) {
        Text node = getFirstNode(this.elementIdentifier);
        node.setData(uuid);
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

    public void setElement(Element elem) {
        this.element.appendChild(elem);
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
     * Set the id of this security context token.
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
