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

package org.apache.ws.security.spnego;

import java.security.Principal;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import org.apache.ws.security.WSSecurityException;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.MessageProp;

/**
 * SPNEGO Token.
 */
public class SpnegoToken {
    
    private static final org.apache.commons.logging.Log LOG = 
        org.apache.commons.logging.LogFactory.getLog(SpnegoToken.class);
    
    private GSSContext secContext;
    private byte[] token;

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
            if (LOG.isDebugEnabled()) {
                LOG.debug(ex.getMessage(), ex);
            }
            throw new WSSecurityException(
                WSSecurityException.FAILURE,
                "kerberosLoginError", 
                new Object[] {ex.getMessage()}
            );
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("Successfully authenticated to the TGT");
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
        SpnegoClientAction action = new SpnegoClientAction(serviceName);
        token = (byte[])Subject.doAs(clientSubject, action);
        if (token == null) {
            throw new WSSecurityException(
                WSSecurityException.FAILURE, "kerberosServiceTicketError"
            );
        }
        
        secContext = action.getContext();
        if (LOG.isDebugEnabled()) {
            LOG.debug("Successfully retrieved a service ticket");
        }
        
    }
    
    /**
     * Get the SPNEGO token that was created in retrieveServiceTicket().
     */
    public byte[] getToken() {
        return token;
    }
    
    /**
     * Unwrap a key
     */
    public byte[] unwrapKey(byte[] secret) throws WSSecurityException {
        MessageProp mProp = new MessageProp(0, true);
        try {
            return secContext.unwrap(secret, 0, secret.length, mProp);
        } catch (GSSException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Error in cleaning up a GSS context", e);
            }
            throw new WSSecurityException(
                WSSecurityException.FAILURE, "spnegoKeyError"
            );
        }
    }
    
    public void clear() {
        token = null;
        try {
            secContext.dispose();
        } catch (GSSException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Error in cleaning up a GSS context", e);
            }
        }
    }
    
}
