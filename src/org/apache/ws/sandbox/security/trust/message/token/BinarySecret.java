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

import org.apache.ws.security.trust.TrustConstants;
import org.apache.ws.security.trust.WSTrustException;
import org.apache.ws.security.util.DOM2Writer;
import org.apache.xml.utils.QName;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

/**
 *
 * @author Dimuthu Leelarathne. muthulee@yahoo.com
 */
public class BinarySecret {
	
    public static final QName TOKEN =new QName(TrustConstants.WST_NS,"BinarySecret");
    
    public static final String PRIVATE_KEY = "http://schemas.xmlsoap.org/ws/2004/04/security/trust/AsymmetricKey";
	public static final String SYMMETRIC_KEY ="http://schemas.xmlsoap.org/ws/2004/04/security/trust/SymmetricKey";
	public static final String NONCE_VAL="http://schemas.xmlsoap.org/ws/2004/04/security/trust/Nonce";
	
    protected Element element = null;
    
    protected String typeAttr = null;
    
    
//    protected WSSConfig wssConfig = WSSConfig.getDefaultWSConfig();

    
    /**
     * Constructor.
     * <p/>
     *
     * @param wssConfig
     * @param elem
     */
    public BinarySecret(Element elem)
        throws WSTrustException {
			this.element = elem;
					QName el = new QName(this.element.getNamespaceURI(),
							this.element.getLocalName());
					if (!el.equals(TOKEN)) {
						throw new WSTrustException();
					}
        } 
					

    /**
     * Constructor.
     * <p/>
     *
     * @param wssConfig
     * @param doc
     */
    public BinarySecret(Document doc) {
        this.element = doc.createElementNS(TrustConstants.WST_NS,
		"wst:BinarySecret");
    }

    /*
     * Here the methods that handle the direct reference inside
     * a SecurityTokenReference
     */

    /**
     * set the Type.
     * Set one of the three types.
     * @param ref
     */
    public void setTypeAttribute(String type) {
    	this.typeAttr=type;
    	this.element.setAttribute("Type", typeAttr);
    }

    public String getTypeAttribute() {
    	return this.element.getAttribute("Type");
    }

    /**
     * Sets the text node
     *
     * @param val
     */
    public void setBinarySecretValue(String val) {
        this.element.appendChild(
            element.getOwnerDocument().createTextNode(val));
    }

    /**
    * return the value of the text node
    	   *
    	   * @return
    	   */
    public String getBinarySecretValue() {
        String val = "";
        if (this.element.getFirstChild().getNodeType() != Node.TEXT_NODE) {
            return null;
        }
        val = this.element.getFirstChild().getNodeValue();
        return val;
    }

    /**
    	* get the element
    	*
    	* @return
    	*/
    public Element getElement() {
        return this.element;
    }

    /**
    	* set the element
    	*
    	* @param element
    	*/
    public void setElement(Element element) {
        this.element = element;
    }

    public String toString() {
        return DOM2Writer.nodeToString((Node) this.element);
    }

}
