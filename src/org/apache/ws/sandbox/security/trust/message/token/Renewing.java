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
 * This optional element is used to specify renew semantics for types that support this operation.
 * Also can be used request for a token that can be renewed.
 *
 */
public class Renewing {
    public static final QName TOKEN = new QName(TrustConstants.WST_NS, TrustConstants.RENEWING_LN,TrustConstants.WST_PREFIX);
        Element element=null;
        //to request a renewable token.
        boolean isAllowed=true;
        //to indicate that a renewable token is    acceptable if the requested duration exceeds the limit of the issuance service.
        boolean isOK=false;
        
        /**
         * Constructor for Renewing
         * @param elem
         * @throws WSSecurityException
         */    
        public Renewing(Element elem) throws WSSecurityException {    
            this.element = elem;
             QName el = new QName(this.element.getNamespaceURI(), this.element.getLocalName());
             if (!el.equals(TOKEN)) {
                 throw new WSSecurityException(WSSecurityException.INVALID_SECURITY_TOKEN, "badTokenType", new Object[]{el});
             } 

        }
        /**
         * Constructor for Renewing
         * 
         * @param doc
         */
        public Renewing(Document doc) {
            this.element = doc.createElementNS(TOKEN.getNamespaceURI(), TOKEN.getPrefix()+":"+TOKEN.getLocalPart());
            WSSecurityUtil.setNamespace(this.element, TrustConstants.WST_NS, TrustConstants.WST_PREFIX);
            this.element.appendChild(doc.createTextNode(""));
            this.element.setAttribute("OK", String.valueOf(isOK));
            this.element.setAttribute("Allow", String.valueOf(isAllowed));
        }
        /**
         * Constructor for Renewing
         * 
         * @param doc
         * @param isOK
         * @param isAllowed
         */
        public Renewing(Document doc,boolean isOK,boolean isAllowed) {
            this.element = doc.createElementNS(TOKEN.getNamespaceURI(), TOKEN.getPrefix()+":"+TOKEN.getLocalPart());
            WSSecurityUtil.setNamespace(this.element, TrustConstants.WST_NS, TrustConstants.WST_PREFIX);
            this.element.appendChild(doc.createTextNode(""));
            this.element.setAttribute("OK", String.valueOf(isOK));
            this.element.setAttribute("Allow", String.valueOf(isAllowed));
        }

        /**
         * get the first Node of the element
         * @return
         */
        public Text getFirstNode() {
            Node node = this.element.getFirstChild();
            return ((node != null) && node instanceof Text) ? (Text) node : null;
        }
    

        /**
         * getthe Renewing element
         * @return
         */
        public Element getElement() {
            return element;
        }

        /**
         * Set the Renewing element
         * @param element
         */
        public void setElement(Element element) {
            this.element = element;
        }

    
        /**
         * to get the element as a String
         */
        public String toString() {
          return DOM2Writer.nodeToString((Node)this.element);
        }
        
        public void setAllow(boolean allowed){        
            this.isAllowed=allowed;
            this.element.setAttribute("Allow", String.valueOf(allowed));
        }
        
        public String getAllow(){        
            return this.element.getAttribute("Allow");
        }
        
        public void setOK(boolean isOK){    
            this.isOK=isOK;    
            this.element.setAttribute("OK", String.valueOf(isOK));
        }
            
        public String getOK(){
            return this.element.getAttribute("OK");
        }

}
