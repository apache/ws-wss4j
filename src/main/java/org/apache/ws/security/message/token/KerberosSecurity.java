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
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * Kerberos Security Token.
 */
public class KerberosSecurity extends BinarySecurity {
    
    /**
     * This constructor creates a new Kerberos token object and initializes
     * it from the data contained in the element.
     *
     * @param elem the element containing the Kerberos token data
     * @throws WSSecurityException
     */
    public KerberosSecurity(Element elem) throws WSSecurityException {
        this(elem, true);
    }
    
    /**
     * This constructor creates a new Kerberos token object and initializes
     * it from the data contained in the element.
     *
     * @param elem the element containing the Kerberos token data
     * @param bspCompliant Whether the token is processed according to the BSP spec
     * @throws WSSecurityException
     */
    public KerberosSecurity(Element elem, boolean bspCompliant) throws WSSecurityException {
        super(elem, bspCompliant);
    }

    /**
     * This constructor creates a new Kerberos element.
     *
     * @param doc
     */
    public KerberosSecurity(Document doc) {
        super(doc);
    }
    
    /**
     * Return true if this token is a Kerberos V5 AP REQ token
     */
    public boolean isV5ApReq() {
        String type = getValueType();
        if (WSConstants.WSS_KRB_V5_AP_REQ.equals(type)
            || WSConstants.WSS_KRB_V5_AP_REQ1510.equals(type)
            || WSConstants.WSS_KRB_V5_AP_REQ4120.equals(type)) {
            return true;
        }
        return false;
    }
    
    /**
     * Return true if this token is a Kerberos GSS V5 AP REQ token
     */
    public boolean isGssV5ApReq() {
        String type = getValueType();
        if (WSConstants.WSS_GSS_KRB_V5_AP_REQ.equals(type)
            || WSConstants.WSS_GSS_KRB_V5_AP_REQ1510.equals(type)
            || WSConstants.WSS_GSS_KRB_V5_AP_REQ4120.equals(type)) {
            return true;
        }
        return false;
    }

}
