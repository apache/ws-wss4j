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
import org.apache.xml.security.utils.Base64;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.Text;

import javax.xml.namespace.QName;

/**
 * Binary Security Token.
 * <p/>
 * 
 * @author Davanum Srinivas (dims@yahoo.com).
 */
public class BinarySecurity {
    public static final QName TOKEN = new QName(WSConstants.WSSE_NS, "BinarySecurityToken");
    public static final QName TOKEN_KI = new QName(WSConstants.WSSE_NS, "KeyIdentifier");
    public static final String BASE64_BINARY = "Base64Binary";
    public static String BASE64_ENCODING = null; // set in a static block later 
    protected Element element = null;

    static {
        if (WSConstants.COMPLIANCE_MODE <= WSConstants.OASIS_2002_12) {
            BASE64_ENCODING = WSConstants.WSSE_PREFIX + ":" + BASE64_BINARY;
        } else {
            BASE64_ENCODING = WSConstants.SOAPMESSAGE_NS + "#Base64Binary";
        }
    }
    
    /**
     * Constructor.
     * <p/>
     * 
     * @param elem 
     * @throws WSSecurityException 
     */
    public BinarySecurity(Element elem) throws WSSecurityException {
        this.element = elem;
        QName el = new QName(this.element.getNamespaceURI(), this.element.getLocalName());
        if (!el.equals(TOKEN) && !el.equals(TOKEN_KI)) {
            throw new WSSecurityException(WSSecurityException.INVALID_SECURITY_TOKEN, "badTokenType", new Object[]{el});
        }
        if (!getEncodingType().endsWith(BASE64_BINARY)) {
            throw new WSSecurityException(WSSecurityException.INVALID_SECURITY_TOKEN, "badEncoding", new Object[]{getEncodingType()});
        }
    }

    /**
     * Constructor.
     * <p/>
     * 
     * @param doc 
     */
    public BinarySecurity(Document doc) {
        this.element = doc.createElementNS(WSConstants.WSSE_NS, "wsse:BinarySecurityToken");
        WSSecurityUtil.setNamespace(this.element, WSConstants.WSSE_NS, WSConstants.WSSE_PREFIX);
        setEncodingType(BASE64_ENCODING);
        this.element.appendChild(doc.createTextNode(""));
    }

    /**
     * get the value type.
     * <p/>
     * 
     * @return 
     */
    public String getValueType() {
        String valueType = this.element.getAttribute("ValueType");
        // also attempt to get the attribute in case it was qualified
        // NYI: still need to check for all supported namespaces here
        if (valueType.length() == 0) {
            valueType = element.getAttributeNS(WSConstants.WSSE_NS, "ValueType");
        }
        return valueType;
    }

    /**
     * set the value type.
     * <p/>
     * 
     * @param type 
     */
    protected void setValueType(String type) {
        if (WSConstants.COMPLIANCE_MODE <= WSConstants.OASIS_2002_12) {
            this.element.setAttributeNS(WSConstants.WSSE_NS, WSConstants.WSSE_PREFIX + ":ValueType", type);
        } else {
            this.element.setAttributeNS(null, "ValueType", type);
        }
    }

    /**
     * get the encoding type.
     * <p/>
     * 
     * @return 
     */
    public String getEncodingType() {
        String encodingType = this.element.getAttribute("EncodingType");
        // attempt to get the attribute in case it was qualified
        // NYI: still need to check for all supported namespaces here
        if (encodingType.length() == 0) {
            encodingType = this.element.getAttributeNS(WSConstants.WSSE_NS, "EncodingType");
        }
        return encodingType;
    }

    /**
     * set the encoding type.
     * <p/>
     * 
     * @param encoding 
     */
    protected void setEncodingType(String encoding) {
        if (WSConstants.COMPLIANCE_MODE <= WSConstants.OASIS_2002_12) {
            this.element.setAttributeNS(WSConstants.WSSE_NS, WSConstants.WSSE_PREFIX + ":EncodingType", encoding);
        } else {
            this.element.setAttributeNS(null, "EncodingType", encoding);
        }
    }

    /**
     * get the byte array containing token information.
     * <p/>
     * 
     * @return 
     */
    public byte[] getToken() {
        Text node = getFirstNode();
        if (node == null) {
            return null;
        }
        try {
            return Base64.decode(node.getData());
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * set the token information.
     * <p/>
     * 
     * @param data 
     */
    protected void setToken(byte[] data) {
        if (data == null) {
            throw new IllegalArgumentException("data == null");
        }
        Text node = getFirstNode();
        node.setData(Base64.encode(data));
    }

    /**
     * return the first text node.
     * <p/>
     * 
     * @return 
     */
    protected Text getFirstNode() {
        Node node = this.element.getFirstChild();
        return ((node != null) && node instanceof Text) ? (Text) node : null;
    }

    /**
     * return the dom element.
     * <p/>
     * 
     * @return 
     */
    public Element getElement() {
        return this.element;
    }

    /**
     * get the id.
     * <p/>
     * 
     * @return 
     */
    public String getID() {
        return this.element.getAttributeNS(WSConstants.WSU_NS, "Id");
    }

    /**
     * set the id.
     * <p/>
     * 
     * @param id 
     */
    public void setID(String id) {
        String prefix = WSSecurityUtil.setNamespace(this.element, WSConstants.WSU_NS, WSConstants.WSU_PREFIX);
        this.element.setAttributeNS(WSConstants.WSU_NS, prefix + ":Id", id);
    }

    /**
     * return the string representation of the token.
     * <p/>
     * 
     * @return 
     */
    public String toString() {
        return DOM2Writer.nodeToString((Node) this.element);
    }
}
