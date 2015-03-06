/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.wss4j.dom.message.token;

import java.io.IOException;
import java.util.Arrays;

import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.common.bsp.BSPRule;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.util.DOM2Writer;
import org.apache.wss4j.common.util.XMLUtils;
import org.apache.wss4j.dom.bsp.BSPEnforcer;
import org.apache.wss4j.dom.util.WSSecurityUtil;
import org.apache.xml.security.utils.Base64;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.Text;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.xml.namespace.QName;

/**
 * Binary Security Token.
 */
public class BinarySecurity {
    public static final QName TOKEN_BST = new QName(WSConstants.WSSE_NS, "BinarySecurityToken");
    public static final QName TOKEN_KI = new QName(WSConstants.WSSE_NS, "KeyIdentifier");
    public static final String BASE64_ENCODING = WSConstants.SOAPMESSAGE_NS + "#Base64Binary";
    private static final org.slf4j.Logger LOG = 
        org.slf4j.LoggerFactory.getLogger(BinarySecurity.class);
    
    private Element element;

    /**
     * Constructor.
     * @param elem The BinarySecurityToken element to process
     * @param bspEnforcer a BSPEnforcer instance to enforce BSP rules
     * @throws WSSecurityException
     */
    public BinarySecurity(Element elem, BSPEnforcer bspEnforcer) throws WSSecurityException {
        element = elem;
        QName el = new QName(element.getNamespaceURI(), element.getLocalName());
        if (!(el.equals(TOKEN_BST) || el.equals(TOKEN_KI))) {
            throw new WSSecurityException(
                WSSecurityException.ErrorCode.INVALID_SECURITY_TOKEN, 
                "unhandledToken", el);
        }
        String encoding = getEncodingType();
        if (encoding == null || "".equals(encoding)) {
            bspEnforcer.handleBSPRule(BSPRule.R3029);
        }
        
        if (!BASE64_ENCODING.equals(encoding)) {
            bspEnforcer.handleBSPRule(BSPRule.R3030);
        }
        
        String valueType = getValueType();
        if (valueType == null || "".equals(valueType)) {
            bspEnforcer.handleBSPRule(BSPRule.R3031);
        }
    }

    /**
     * Constructor.
     * 
     * @param doc 
     */
    public BinarySecurity(Document doc) {
        element = doc.createElementNS(WSConstants.WSSE_NS, "wsse:BinarySecurityToken");
        setEncodingType(BASE64_ENCODING);
        element.appendChild(doc.createTextNode(""));
    }
    
    /**
     * Create a BinarySecurityToken via a CallbackHandler
     * @param callbackHandler
     * @throws WSSecurityException
     */
    public BinarySecurity(CallbackHandler callbackHandler) throws WSSecurityException {
        if (callbackHandler == null) {
            LOG.debug("Trying to create a BinarySecurityToken via a null CallbackHandler");
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE);
        }
        TokenElementCallback[] callback = new TokenElementCallback[] { new TokenElementCallback() };

        try {
            callbackHandler.handle(callback);
        } catch (IOException | UnsupportedCallbackException e) {
            throw new IllegalStateException(
                "Exception while creating a token element", e
            );
        }
        element = callback[0].getTokenElement();
        if (element == null) {
            LOG.debug("CallbackHandler did not return a token element");
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE);
        }
    }
    
    /**
     * Add the WSSE Namespace to this BST. The namespace is not added by default for
     * efficiency purposes.
     */
    public void addWSSENamespace() {
        WSSecurityUtil.setNamespace(element, WSConstants.WSSE_NS, WSConstants.WSSE_PREFIX);
    }
    
    /**
     * Add the WSU Namespace to this BST. The namespace is not added by default for
     * efficiency purposes.
     */
    public void addWSUNamespace() {
        WSSecurityUtil.setNamespace(element, WSConstants.WSU_NS, WSConstants.WSU_PREFIX);
    }

    /**
     * get the value type.
     * 
     * @return the value type
     */
    public String getValueType() {
        return element.getAttributeNS(null, "ValueType");
    }

    /**
     * set the value type.
     * 
     * @param type 
     */
    public void setValueType(String type) {
        if (type != null) {
            element.setAttributeNS(null, "ValueType", type);
        }
    }

    /**
     * get the encoding type.
     * 
     * @return the encoding type.
     */
    public String getEncodingType() {
        return element.getAttributeNS(null, "EncodingType");
    }

    /**
     * set the encoding type.
     * 
     * @param encoding 
     */
    public void setEncodingType(String encoding) {
        if (encoding != null) {
            element.setAttributeNS(null, "EncodingType", encoding);
        }
    }

    /**
     * get the byte array containing token information.
     * 
     * @return the byte array containing token information
     */
    public byte[] getToken() {
        try {
            String text = XMLUtils.getElementText(element);
            if (text == null) {
                return null;
            }
            return Base64.decode(text);
        } catch (Exception ex) {
            if (LOG.isDebugEnabled()) {
                LOG.debug(ex.getMessage(), ex);
            }
            return null;
        }
    }

    /**
     * set the token information.
     * 
     * @param data 
     */
    public void setToken(byte[] data) {
        if (data == null) {
            throw new IllegalArgumentException("data == null");
        }
        Text node = getFirstNode();
        node.setData(Base64.encode(data));
    }

    /**
     * return the first text node.
     * 
     * @return the first text node.
     */
    protected Text getFirstNode() {
        Node node = element.getFirstChild();
        return node != null && Node.TEXT_NODE == node.getNodeType() ? (Text) node : null;
    }

    /**
     * return the dom element.
     * 
     * @return the dom element.
     */
    public Element getElement() {
        return element;
    }

    /**
     * get the id.
     * 
     * @return the WSU ID of this element
     */
    public String getID() {
        return element.getAttributeNS(WSConstants.WSU_NS, "Id");
    }

    /**
     * set the id.
     * 
     * @param id 
     */
    public void setID(String id) {
        element.setAttributeNS(WSConstants.WSU_NS, WSConstants.WSU_PREFIX + ":Id", id);
    }

    /**
     * return the string representation of the token.
     * 
     * @return the string representation of the token.
     */
    public String toString() {
        return DOM2Writer.nodeToString(element);
    }
    
    @Override
    public int hashCode() {
        int result = 17;
        byte[] token = getToken();
        if (token != null) {
            result = 31 * result + Arrays.hashCode(token);
        }
        result = 31 * result + getValueType().hashCode();
        result = 31 * result + getEncodingType().hashCode();
        
        return result;
    }
    
    @Override
    public boolean equals(Object object) {
        if (!(object instanceof BinarySecurity)) {
            return false;
        }
        BinarySecurity binarySecurity = (BinarySecurity)object;
        
        byte[] token = binarySecurity.getToken();
        if (!Arrays.equals(token, getToken())) {
            return false;
        }
        String valueType = binarySecurity.getValueType();
        if (!valueType.equals(getValueType())) {
            return false;
        }
        String encodingType = binarySecurity.getEncodingType();
        if (!encodingType.equals(getEncodingType())) {
            return false;
        }
        return true;
    }
}
