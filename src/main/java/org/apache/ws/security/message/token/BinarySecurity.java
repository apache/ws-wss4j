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

package org.apache.ws.security.message.token;

import java.io.IOException;
import java.util.Arrays;

import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.util.DOM2Writer;
import org.apache.ws.security.util.WSSecurityUtil;
import org.apache.ws.security.util.Base64;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.Text;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.xml.namespace.QName;

/**
 * Binary Security Token.
 * 
 * @author Davanum Srinivas (dims@yahoo.com).
 * @author Werner Dittmann (Werner.Dittmann@t-onile.de).
 */
public class BinarySecurity {
    public static final QName TOKEN_BST = new QName(WSConstants.WSSE_NS, "BinarySecurityToken");
    public static final QName TOKEN_KI = new QName(WSConstants.WSSE_NS, "KeyIdentifier");
    public static final String BASE64_ENCODING = WSConstants.SOAPMESSAGE_NS + "#Base64Binary";
    private static final org.apache.commons.logging.Log LOG = 
        org.apache.commons.logging.LogFactory.getLog(BinarySecurity.class);
    protected Element element = null;

    /**
     * Constructor.
     * 
     * @param elem The BinarySecurityToken element to process
     * @throws WSSecurityException 
     */
    public BinarySecurity(Element elem) throws WSSecurityException {
        this(elem, true);
    }

    /**
     * Constructor.
     * @param elem The BinarySecurityToken element to process
     * @param bspCompliant whether the processing conforms to the BSP spec
     * @throws WSSecurityException
     */
    public BinarySecurity(Element elem, boolean bspCompliant) throws WSSecurityException {
        element = elem;
        QName el = new QName(element.getNamespaceURI(), element.getLocalName());
        if (!(el.equals(TOKEN_BST) || el.equals(TOKEN_KI))) {
            throw new WSSecurityException(
                WSSecurityException.INVALID_SECURITY_TOKEN, 
                "unhandledToken",
                new Object[] {el}
            );
        }
        String encoding = getEncodingType();
        if (bspCompliant && !BASE64_ENCODING.equals(encoding)) {
            // The EncodingType attribute must be specified, and must be equal to Base64Binary
            throw new WSSecurityException(
                WSSecurityException.INVALID_SECURITY_TOKEN,
                "badEncodingType", 
                new Object[] {encoding}
            );
        }
        
        String valueType = getValueType();
        if (bspCompliant && (valueType == null || "".equals(valueType))) {
            throw new WSSecurityException(
                WSSecurityException.INVALID_SECURITY_TOKEN,
                "invalidValueType",
                new Object[]{valueType}
            );
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
            throw new WSSecurityException(WSSecurityException.FAILURE);
        }
        TokenElementCallback[] callback = new TokenElementCallback[] { new TokenElementCallback() };

        try {
            callbackHandler.handle(callback);
        } catch (IOException e) {
            throw new IllegalStateException(
                "IOException while creating a token element", e
            );
        } catch (UnsupportedCallbackException e) {
            throw new IllegalStateException(
                "UnsupportedCallbackException while creating a token element", e
            );
        }
        element = callback[0].getTokenElement();
        if (element == null) {
            LOG.debug("CallbackHandler did not return a token element");
            throw new WSSecurityException(WSSecurityException.FAILURE);
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
        return element.getAttribute("ValueType");
    }

    /**
     * set the value type.
     * 
     * @param type 
     */
    public void setValueType(String type) {
        element.setAttributeNS(null, "ValueType", type);
    }

    /**
     * get the encoding type.
     * 
     * @return the encoding type.
     */
    public String getEncodingType() {
        return element.getAttribute("EncodingType");
    }

    /**
     * set the encoding type.
     * 
     * @param encoding 
     */
    public void setEncodingType(String encoding) {
        element.setAttributeNS(null, "EncodingType", encoding);
    }

    /**
     * get the byte array containing token information.
     * 
     * @return the byte array containing token information
     */
    public byte[] getToken() {
        Node node = element.getFirstChild();
        StringBuilder builder = new StringBuilder();
        while (node != null) {
            if (Node.TEXT_NODE == node.getNodeType()) {
                builder.append(((Text)node).getData());
            }
            node = node.getNextSibling();
        }
                
        try {
            return Base64.decode(builder.toString());
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
        return (node != null && Node.TEXT_NODE == node.getNodeType()) ? (Text) node : null;
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
        return DOM2Writer.nodeToString((Node)element);
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
