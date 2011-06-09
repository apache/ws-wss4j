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

import java.util.Arrays;

import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.util.DOM2Writer;
import org.apache.ws.security.util.WSSecurityUtil;
import org.apache.ws.security.util.Base64;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;


/**
 * Signature Confirmation element.
 *
 *
 * @author Werner Dittmann (Werner.Dittmann@t-online.de)
 */
public class SignatureConfirmation {

    public static final String SC_VALUE_ATTR = "Value"; 
    protected Element element = null;
    private byte[] signatureValue = null;
    
    /**
     * Constructs a <code>SignatureConfirmation</code> object and parses the
     * <code>wsse11:SignatureConfirmation</code> element to initialize it.
     *
     * @param elem the <code>wsse11:SignatureCOnfirmation</code> element that
     *             contains the confirmation data
     */
    public SignatureConfirmation(Element elem) throws WSSecurityException {
        element = elem;
        String sv = element.getAttribute(SC_VALUE_ATTR);
        if (sv != null) {
            signatureValue = Base64.decode(sv);
        }
    }

    /**
     * Constructs a <code>SignatureConfirmation</code> object according
     * to the defined parameters.
     *
     * @param doc the SOAP envelope as <code>Document</code>
     * @param signVal the Signature value as byte[] of <code>null</code> 
     * if no value available.
     */
    public SignatureConfirmation(Document doc, byte[] signVal) {
        element = 
            doc.createElementNS(
                WSConstants.WSSE11_NS, 
                WSConstants.WSSE11_PREFIX + ":"  + WSConstants.SIGNATURE_CONFIRMATION_LN
            );
        WSSecurityUtil.setNamespace(element, WSConstants.WSSE11_NS, WSConstants.WSSE11_PREFIX);
        if (signVal != null) {
            String sv = Base64.encode(signVal);
            element.setAttributeNS(null, SC_VALUE_ATTR, sv);
        }
    }
    
    /**
     * Add the WSU Namespace to this SC. The namespace is not added by default for
     * efficiency purposes.
     */
    public void addWSUNamespace() {
        WSSecurityUtil.setNamespace(element, WSConstants.WSU_NS, WSConstants.WSU_PREFIX);
    }

    /**
     * Returns the dom element of this <code>SignatureConfirmation</code> object.
     *
     * @return the <code>wsse11:SignatureConfirmation</code> element
     */
    public Element getElement() {
        return element;
    }

    /**
     * Returns the string representation of the token.
     *
     * @return a XML string representation
     */
    public String toString() {
        return DOM2Writer.nodeToString((Node)element);
    }
    
    /**
     * Set wsu:Id attribute of this SignatureConfirmation element.
     * @param id
     */
    public void setID(String id) {
        element.setAttributeNS(WSConstants.WSU_NS, WSConstants.WSU_PREFIX + ":Id", id);
    }
    
    /**
     * Returns the value of the wsu:Id attribute
     * @return the WSU ID
     */
    public String getID() {
        return element.getAttributeNS(WSConstants.WSU_NS, "Id");
    }

    /**
     * @return Returns the signatureValue.
     */
    public byte[] getSignatureValue() {
        return signatureValue;
    }
    
    @Override
    public int hashCode() {
        int result = 17;
        if (signatureValue != null) {
            result = 31 * result + Arrays.hashCode(signatureValue);
        }
        return result;
    }
    
    @Override
    public boolean equals(Object object) {
        if (!(object instanceof SignatureConfirmation)) {
            return false;
        }
        SignatureConfirmation signatureConfirmation = (SignatureConfirmation)object;
        byte[] sigValue = signatureConfirmation.getSignatureValue();
        if (!Arrays.equals(sigValue, getSignatureValue())) {
            return false;
        }
        return true;
    }
    
}
