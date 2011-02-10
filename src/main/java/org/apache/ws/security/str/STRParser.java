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

package org.apache.ws.security.str;

import org.apache.ws.security.WSDocInfo;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;
import org.w3c.dom.Element;

import java.security.Principal;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Map;
import javax.security.auth.callback.CallbackHandler;

/**
 * This interface describes a pluggable way of extracting credentials from SecurityTokenReference
 * elements. The implementations are used by various processors.
 */
public interface STRParser {
    
    /**
     * Set whether we should process tokens according to the BSP spec
     * @param bspCompliant whether we should process tokens according to the BSP spec
     */
    public void setBspCompliant(boolean bspCompliant);
    
    /**
     * Parse a SecurityTokenReference element and extract credentials.
     * 
     * @param strElement The SecurityTokenReference element
     * @param crypto The crypto instance used to extract credentials
     * @param cb The CallbackHandler instance to supply passwords
     * @param wsDocInfo The WSDocInfo object to access previous processing results
     * @param parameters A set of implementation-specific parameters
     * @throws WSSecurityException
     */
    public void parseSecurityTokenReference(
        Element strElement,
        Crypto crypto,
        CallbackHandler cb,
        WSDocInfo wsDocInfo,
        Map<String, Object> parameters
    ) throws WSSecurityException;
    
    /**
     * Get the X509Certificates associated with this SecurityTokenReference
     * @return the X509Certificates associated with this SecurityTokenReference
     */
    public X509Certificate[] getCertificates();
    
    /**
     * Get the Principal associated with this SecurityTokenReference
     * @return the Principal associated with this SecurityTokenReference
     */
    public Principal getPrincipal();
    
    /**
     * Get the PublicKey associated with this SecurityTokenReference
     * @return the PublicKey associated with this SecurityTokenReference
     */
    public PublicKey getPublicKey();
    
    /**
     * Get the Secret Key associated with this SecurityTokenReference
     * @return the Secret Key associated with this SecurityTokenReference
     */
    public byte[] getSecretKey();
    
}
