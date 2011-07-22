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

import java.security.Principal;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSecurityException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * Kerberos Security Token.
 */
public class KerberosSecurity extends BinarySecurity {
    
    private static org.apache.commons.logging.Log log =
        org.apache.commons.logging.LogFactory.getLog(KerberosSecurity.class);
    
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

    /**
     * Retrieve a service ticket from a KDC using the Kerberos JAAS module, and set it in this
     * BinarySecurityToken.
     * @param jaasLoginModuleName the JAAS Login Module name to use
     * @param callbackHandler a CallbackHandler instance to retrieve a password (optional)
     * @param serviceName the desired Kerberized service
     * @throws WSSecurityException
     */
    public void retrieveServiceTicket(
        String jaasLoginModuleName, 
        CallbackHandler callbackHandler,
        String serviceName
    ) throws WSSecurityException {
        // Get a TGT from the KDC using JAAS
        LoginContext loginContext = null;
        try {
            if (callbackHandler == null) {
                loginContext = new LoginContext(jaasLoginModuleName);
            } else {
                loginContext = new LoginContext(jaasLoginModuleName, callbackHandler);
            }
            loginContext.login();
        } catch (LoginException ex) {
            if (log.isDebugEnabled()) {
                log.debug(ex.getMessage(), ex);
            }
            throw new WSSecurityException(
                WSSecurityException.FAILURE,
                "kerberosLoginError", 
                new Object[] {ex.getMessage()}
            );
        }
        if (log.isDebugEnabled()) {
            log.debug("Successfully authenticated to the TGT");
        }
        
        Subject clientSubject = loginContext.getSubject();
        Set<Principal> clientPrincipals = clientSubject.getPrincipals();
        if (clientPrincipals.isEmpty()) {
            throw new WSSecurityException(
                WSSecurityException.FAILURE, 
                "kerberosLoginError", 
                new Object[] {"No Client principals found after login"}
            );
        }
        
        // Get the service ticket
        KerberosClientAction action = 
            new KerberosClientAction(clientPrincipals.iterator().next(), serviceName);
        byte[] ticket = Subject.doAs(clientSubject, action);
        if (ticket == null) {
            throw new WSSecurityException(
                WSSecurityException.FAILURE, "kerberosServiceTicketError"
            );
        }
        if (log.isDebugEnabled()) {
            log.debug("Successfully retrieved a service ticket");
        }
        
        setToken(ticket);
        
        if ("".equals(getValueType())) {
            setValueType(WSConstants.WSS_GSS_KRB_V5_AP_REQ);
        }
    }
    
    
}
