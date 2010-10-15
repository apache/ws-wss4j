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

import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.util.DOM2Writer;
import org.apache.ws.security.util.WSSecurityUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

/**
 * An X509Data token.
 */
public final class DOMX509Data {
    private final Element element;
    private DOMX509IssuerSerial x509IssuerSerial;
    
    /**
     * Constructor.
     */
    public DOMX509Data(Element x509DataElement) throws WSSecurityException {
        element = x509DataElement;
        //
        // Parse X509IssuerSerial child
        //
        Element issuerSerialElement = 
            WSSecurityUtil.getDirectChildElement(
                element, WSConstants.X509_ISSUER_SERIAL_LN, WSConstants.SIG_NS
            );
        x509IssuerSerial = new DOMX509IssuerSerial(issuerSerialElement);
    }

    /**
     * Constructor.
     */
    public DOMX509Data(Document doc, DOMX509IssuerSerial domIssuerSerial) {
        element = 
            doc.createElementNS(
                WSConstants.SIG_NS, WSConstants.SIG_PREFIX + ":" + WSConstants.X509_DATA_LN
            );
        
        element.appendChild(domIssuerSerial.getElement());
    }
    
    /**
     * Return true if this X509Data element contains a X509IssuerSerial element
     */
    public boolean containsIssuerSerial() {
        if (x509IssuerSerial == null) {
            return false;
        }
        return true;
    }
    
    /**
     * Return a DOMX509IssuerSerial object in this X509Data structure
     */
    public DOMX509IssuerSerial getIssuerSerial() {
        return x509IssuerSerial;
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
     * return the string representation of the token.
     * 
     * @return the string representation of the token.
     */
    public String toString() {
        return DOM2Writer.nodeToString((Node)element);
    }
    
}
