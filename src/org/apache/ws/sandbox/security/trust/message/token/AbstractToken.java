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
package org.apache.ws.security.trust.message.token;

import javax.xml.namespace.QName;

import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.trust.TrustConstants;
import org.apache.ws.security.trust.WSTrustException;
import org.apache.ws.security.util.DOM2Writer;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.w3c.dom.Text;

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
	protected Document document;
	
	/**
	 * Create a new token with the given document
	 * @param doc
	 */
	public AbstractToken(Document doc) {
		QName token = this.getToken();
		this.element = doc.createElementNS(token.getNamespaceURI(), TrustConstants.WST_PREFIX + ":" + token.getLocalPart());
		this.document = doc;
	}

	/**
	 * Tihs constructor accepts a DOM Element instance
	 * Will populate the internal properties
	 * @param elem
	 * @throws WSSecurityException
	 */
	public AbstractToken(Element elem) throws WSTrustException {
		QName token = this.getToken();
        QName el =  new QName(elem.getNamespaceURI(), elem.getLocalName());
        if (!el.equals(token))
            throw new WSTrustException(WSTrustException.INVALID_REQUEST, "badTokenType", new Object[]{el});
        
        this.element = elem;
        this.document = elem.getOwnerDocument();
        this.parse(this.element);

	}

	/**
	 * Parses the immediate children of the current token and calls the
	 * deserializeChildElement method or deserializeElementText
	 * @param elem
	 * @throws WSSecurityException
	 */
	public void parse(Element elem) throws WSTrustException {
		NodeList nodeList = elem.getChildNodes();
		
		for(int i = 0; i < nodeList.getLength(); i++) {
			Node tempNode = nodeList.item(i);
			switch(tempNode.getNodeType()) {
				case Node.ELEMENT_NODE:
					this.deserializeChildElement((Element)tempNode);
					break;
				/*
				 * If we don't check for the Text node of a Token like this 
				 * we'll have to run through the children of this dom 
				 * element once again in the constructor of each of the tokens
				 */
				case Node.TEXT_NODE :
					this.setElementTextValue((Text)tempNode);
					break;
			}
		}
	}

	/**
	 * This is called for each of the  immediate 
	 * child elements of type <code>Node.ELEMENT_NODE</code> of this token 
	 * @param elem The child element
	 * @throws WSSecurityException
	 */
	protected abstract void deserializeChildElement(Element elem) throws WSTrustException;

	/**
	 * This is called with a <code>Text</code> node of the
	 * current element
	 * @param textNode
	 */
	protected abstract void setElementTextValue(Text textNode) throws WSTrustException;
	
	
    /**
     * Returns this element
     * @return 
     */
    protected Element getElement() {
        return element;
    }

    /**
     * Sets this element
     * @param element 
     */
    protected void setElement(Element element) {
        this.element = element;
    }
		
    /**
     * To display the token
     */
    public String toString() {
        return DOM2Writer.nodeToString((Node) this.element);
    }
	
    
    protected void addChild(AbstractToken token) {
    	this.element.appendChild(token.getElement());
    }
    
    protected void removeChild(AbstractToken token) {
    	this.element.removeChild(token.getElement());
    }
}
