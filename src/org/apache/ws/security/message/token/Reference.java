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

package org.apache.ws.security.message.token;

import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.util.DOM2Writer;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import javax.xml.namespace.QName;

/**
 * Reference.
 * <p/>
 *
 * @author Davanum Srinivas (dims@yahoo.com).
 */
public class Reference {
    public static final String TOKEN_LNAME = "Reference";
    protected Element element = null;
    protected WSSConfig wssConfig;

    /**
     * Constructor.
     * <p/>
     *
     * @param wssConfig
     * @param elem
     * @throws WSSecurityException
     */
    public Reference(WSSConfig wssConfig, Element elem) throws WSSecurityException {
        if (elem == null) {
            throw new WSSecurityException(WSSecurityException.INVALID_SECURITY,
                    "noReference");
        }
        this.element = elem;
        this.wssConfig = wssConfig;
        boolean nsOK = false;
        if (wssConfig.getProcessNonCompliantMessages()) {
            for (int i = 0; i < WSConstants.WSSE_NS_ARRAY.length; ++i) {
                if (WSConstants.WSSE_NS_ARRAY[i].equals(element.getNamespaceURI())) {
                    nsOK = true;
                    break;
                }
            }
        } else if (wssConfig.getWsseNS().equals(element.getNamespaceURI())) {
            nsOK = true;
        }
        if (!nsOK || !element.getLocalName().equals(TOKEN_LNAME)) {
            QName el = new QName(this.element.getNamespaceURI(), this.element.getLocalName());
            QName token = new QName(wssConfig.getWsseNS(), TOKEN_LNAME);
            throw new WSSecurityException(WSSecurityException.FAILURE,
                    "badElement",
                    new Object[]{token, el});
        }
    }

    /**
     * Constructor.
     * <p/>
     *
     * @param wssConfig
     * @param doc
     */
    public Reference(WSSConfig wssConfig, Document doc) {
        this.wssConfig = wssConfig;
        this.element =
                doc.createElementNS(wssConfig.getWsseNS(), "wsse:" + TOKEN_LNAME);
    }

    /**
     * get the dom element.
     * <p/>
     *
     * @return
     */
    public Element getElement() {
        return this.element;
    }

    /**
     * get the URI.
     * <p/>
     *
     * @return
     */
    public String getValueType() {
        return this.element.getAttribute("ValueType");
    }

    /**
     * get the URI.
     * <p/>
     *
     * @return
     */
    public String getURI() {
        return this.element.getAttribute("URI");
    }

    /**
     * set the Value type.
     * <p/>
     *
     * @param valueType
     */
    public void setValueType(String valueType) {
        this.element.setAttribute("ValueType", valueType);
    }

    /**
     * set the URI.
     * <p/>
     *
     * @param uri
     */
    public void setURI(String uri) {
        this.element.setAttribute("URI", uri);
    }

    /**
     * return the string representation.
     * <p/>
     *
     * @return
     */
    public String toString() {
        return DOM2Writer.nodeToString((Node) this.element);
    }
}
