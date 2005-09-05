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
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.util.DOM2Writer;
import org.apache.ws.security.util.WSSecurityUtil;
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
    public static final QName TOKEN =
        new QName(WSConstants.WSSE_NS, "Reference");
    protected Element element = null;

    /**
     * Constructor.
     * <p/>
     * 
     * @param elem 
     * @throws WSSecurityException 
     */
    public Reference(Element elem) throws WSSecurityException {
        if (elem == null) {
            throw new WSSecurityException(
                WSSecurityException.INVALID_SECURITY,
                "noReference");
        }
        this.element = elem;
        QName el =
            new QName(
                this.element.getNamespaceURI(),
                this.element.getLocalName());
        if (!el.equals(TOKEN)) {
            throw new WSSecurityException(
                WSSecurityException.FAILURE,
                "badElement",
                new Object[] { TOKEN, el });
        }
    }

    /**
     * Constructor.
     * <p/>
     * 
     * @param doc 
     */
    public Reference(Document doc) {
        this.element =
            doc.createElementNS(WSConstants.WSSE_NS, "wsse:Reference");
        WSSecurityUtil.setNamespace(this.element, WSConstants.WSSE_NS, WSConstants.WSSE_PREFIX);
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
