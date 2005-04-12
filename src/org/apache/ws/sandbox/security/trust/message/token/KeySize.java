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

import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.trust.TrustConstants;
import org.apache.ws.security.trust.WSTrustException;
import org.apache.xml.utils.QName;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

/**
 * @author Ruchith Fernando
 */
public class KeySize {

    public static final String KEY_SIZE = "KeySize";
    public static final QName TOKEN = new QName(TrustConstants.WST_NS,KEY_SIZE);

    protected WSSConfig wssConfig = WSSConfig.getDefaultWSConfig();

    protected Element element = null;


    public KeySize(Element elem) throws WSTrustException {
           this.element = elem;
           QName el = new QName(this.element.getNamespaceURI(),
                   this.element.getLocalName());
           if (!el.equals(TOKEN)) {
               throw new WSTrustException("Elemtn is not a 'KeySize' element");
           }
    }


    public KeySize(Document doc) {
        this.element =
            doc.createElementNS(TrustConstants.WST_NS,
                    TrustConstants.WST_PREFIX+":"+KEY_SIZE);
    }

    public void setKeySize(int keySize) {
        this.element.appendChild(this.element.getOwnerDocument().createTextNode(Integer.toString(keySize)));
    }

    /**
     * Returns the key size if set otherwise returns -1
     * @return Returns the key size if set otherwise returns -1
     * @throws WSTrustException
     */
    public int getKeySize() throws WSTrustException {
        Node node = this.element.getFirstChild();
        if(node != null && node.getNodeType() == Node.TEXT_NODE) {
            try {
                return Integer.parseInt(node.getNodeValue());
            } catch (NumberFormatException nfe) {
                throw new WSTrustException("Invalid Key Size : " + nfe.getMessage());
            }
        } else {
            return -1;
        }
    }



    /**
     * @return Returns the element.
     */
    public Element getElement() {
        return element;
    }
    /**
     * @param element The element to set.
     */
    public void setElement(Element element) {
        this.element = element;
    }
}
