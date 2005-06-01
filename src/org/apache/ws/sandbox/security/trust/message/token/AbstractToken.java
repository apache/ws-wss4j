package org.apache.ws.security.trust.message.token;

import javax.xml.namespace.QName;

import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.trust.TrustConstants;
import org.apache.ws.security.util.DOM2Writer;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

/**
 * @author Ruchith Fernando (ruchith.fernando@gmail.com)
 */
public abstract class AbstractToken {

	/**
	 * This metod is used to provide the QName of the element to the 
	 * constructors by the extending types
	 * @return
	 */
	protected abstract QName getToken();
	
	protected Element element;
	
	public AbstractToken(Document doc) {
		QName token = this.getToken();
		this.element = doc.createElementNS(token.getNamespaceURI(), TrustConstants.WST_PREFIX + ":" + token.getLocalPart());
	}
	
	public AbstractToken(Element elem) throws WSSecurityException {
		QName token = this.getToken();
        QName el =  new QName(elem.getNamespaceURI(), elem.getLocalName());
        if (!el.equals(token))
            throw new WSSecurityException(WSSecurityException.INVALID_SECURITY_TOKEN, "badTokenType", new Object[]{el});
        
        this.element = elem;
	}

    /**
     * Returns this element
     * @return 
     */
    public Element getElement() {
        return element;
    }

    /**
     * Sets this element
     * @param element 
     */
    public void setElement(Element element) {
        this.element = element;
    }
		
    /**
     * To display the token
     */
    public String toString() {
        return DOM2Writer.nodeToString((Node) this.element);
    }
	
}
