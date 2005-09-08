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
import org.apache.ws.security.util.WSSecurityUtil;
import org.apache.ws.security.util.Base64;
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
    public static final String BASE64_BINARY = "Base64Binary";
    private String base64Encoding;
    protected Element element = null;
    protected WSSConfig wssConfig = WSSConfig.getDefaultWSConfig();

    public static String TOKEN = "BinarySecurityToken";
    /**
     * Constructor.
     * <p/>
     *
     * @param elem
     * @throws WSSecurityException
     */
    public BinarySecurity(WSSConfig wssConfig, Element elem) throws WSSecurityException {
        this.element = elem;
        this.wssConfig = wssConfig;
        base64Encoding = getBase64EncodingValue(wssConfig);
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
        if (!nsOK ||
                !(element.getLocalName().equals(TOKEN) ||
                element.getLocalName().equals("KeyIdentifier"))) {
            QName el = new QName(this.element.getNamespaceURI(), this.element.getLocalName());
            throw new WSSecurityException(WSSecurityException.INVALID_SECURITY_TOKEN, "badTokenType", new Object[]{el});
        }
        String encoding = getEncodingType();
        if (encoding.length() > 0 && !encoding.endsWith(BASE64_BINARY)) {
            throw new WSSecurityException(WSSecurityException.INVALID_SECURITY_TOKEN, "badEncoding", new Object[]{getEncodingType()});
        }
    }

    /**
     * Constructor.
     * <p/>
     *
     * @param doc
     */
    public BinarySecurity(WSSConfig wssConfig, Document doc) {
        this.wssConfig = wssConfig;
        base64Encoding = getBase64EncodingValue(wssConfig);
        this.element = doc.createElementNS(wssConfig.getWsseNS(), "wsse:BinarySecurityToken");
        WSSecurityUtil.setNamespace(this.element, wssConfig.getWsseNS(), WSConstants.WSSE_PREFIX);
        setEncodingType(base64Encoding);
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
        if (valueType.length() == 0 &&
                (wssConfig.getProcessNonCompliantMessages() || wssConfig.isBSTAttributesQualified())) {
            valueType = WSSecurityUtil.getAttributeValueWSSE(element, "ValueType", null);
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
        if (wssConfig.isBSTAttributesQualified()) {
            this.element.setAttributeNS(wssConfig.getWsseNS(), WSConstants.WSSE_PREFIX + ":ValueType", type);
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
        if (encodingType.length() == 0 &&
                (wssConfig.getProcessNonCompliantMessages() || wssConfig.isBSTAttributesQualified())) {
            encodingType = WSSecurityUtil.getAttributeValueWSSE(element, "EncodingType", null);
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
        if (wssConfig.isBSTAttributesQualified()) {
            this.element.setAttributeNS(wssConfig.getWsseNS(), WSConstants.WSSE_PREFIX + ":EncodingType", encoding);
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
        return this.element.getAttributeNS(wssConfig.getWsuNS(), "Id");
    }

    /**
     * set the id.
     * <p/>
     *
     * @param id
     */
    public void setID(String id) {
        String prefix = WSSecurityUtil.setNamespace(this.element, wssConfig.getWsuNS(), WSConstants.WSU_PREFIX);
        this.element.setAttributeNS(wssConfig.getWsuNS(), prefix + ":Id", id);
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

    public static String getBase64EncodingValue(WSSConfig wssConfig) {
        if (wssConfig.isBSTValuesPrefixed()) {
            return WSConstants.WSSE_PREFIX + ":" + BASE64_BINARY;
        } else {
            return WSConstants.SOAPMESSAGE_NS + "#" + BASE64_BINARY;
        }
    }
}
