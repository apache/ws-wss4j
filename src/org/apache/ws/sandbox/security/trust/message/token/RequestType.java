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
import org.apache.ws.security.util.DOM2Writer;
import org.apache.ws.security.util.WSSecurityUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.Text;
/**
 * @author Malinda Kaushalye
 *
 * RequestType token
 */
public class RequestType {
    public static final QName TOKEN = new QName(TrustConstants.WST_NS, TrustConstants.REQUEST_TYPE_LN,TrustConstants.WST_PREFIX);
    Element element=null;

    /**
     * Constructor for RequestType
     * @param elem
     * @throws WSSecurityException
     */    
    public RequestType(Element elem) throws WSSecurityException {    
        this.element = elem;
         QName el = new QName(this.element.getNamespaceURI(), this.element.getLocalName());
         if (!el.equals(TOKEN)) {
             throw new WSSecurityException(WSSecurityException.INVALID_SECURITY_TOKEN, "badTokenType", new Object[]{el});
         }

    }
    /**
     * Constructor for RequestType
     * @param doc
     */
    public RequestType(Document doc) {
        this.element = doc.createElementNS(TOKEN.getNamespaceURI(), TOKEN.getPrefix()+":"+TOKEN.getLocalPart());
        WSSecurityUtil.setNamespace(this.element, TrustConstants.WST_NS, TrustConstants.WST_PREFIX);
        this.element.appendChild(doc.createTextNode(""));
    }
    
    
    /**
     * get the First Node
     * @return
     */
    public Text getFirstNode() {
        Node node = this.element.getFirstChild();
        return ((node != null) && node instanceof Text) ? (Text) node : null;
    }
        
        
    /**
     * get the element
     * @return
     */
    public Element getElement() {
        return this.element;
    }

    /**
     * set the element
     * @param element
     */
    public void setElement(Element element) {
        this.element = element;
    }
    /**
     * Sets the text node
     * @param val
     */
    public void setValue(String val){    
        this.element.appendChild(element.getOwnerDocument().createTextNode(val));
    }
    
    
    public String toString() {
      return DOM2Writer.nodeToString((Node)this.element);
    }
    /**
     * return the value of the text node
     * @return
     */
    public String getValue(){
        String val="";
        if(this.element.getFirstChild().getNodeType()!=Node.TEXT_NODE){
            return null;
        }
        val=this.element.getFirstChild().getNodeValue();        
        return val;    
    }

}
