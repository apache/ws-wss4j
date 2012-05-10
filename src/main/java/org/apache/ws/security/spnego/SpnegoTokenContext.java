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
 * This class wraps a GSSContext and provides some functionality to obtain and validate spnego tokens.
 */
public class SpnegoTokenContext {
    
    private static final org.apache.commons.logging.Log LOG = 
        org.apache.commons.logging.LogFactory.getLog(SpnegoTokenContext.class);
    
    private GSSContext secContext;
    private byte[] token;
    private boolean mutualAuth;
    private SpnegoClientAction clientAction = new DefaultSpnegoClientAction();
    private SpnegoServiceAction serviceAction = new DefaultSpnegoServiceAction();

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
                new Object[] {ex.getMessage()},
                ex
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
        clientAction.setServiceName(serviceName);
        clientAction.setMutualAuth(mutualAuth);
        token = (byte[])Subject.doAs(clientSubject, clientAction);
        if (token == null) {
            throw new WSSecurityException(
                WSSecurityException.FAILURE, "kerberosServiceTicketError"
            );
        }
        
        secContext = clientAction.getContext();
        if (LOG.isDebugEnabled()) {
            LOG.debug("Successfully retrieved a service ticket");
        }
        
    }
    
    /**
     * Validate a service ticket.
     * @param jaasLoginModuleName
     * @param callbackHandler
     * @param serviceName
     * @param ticket
     * @throws WSSecurityException
     */
    public void validateServiceTicket(
        String jaasLoginModuleName, 
        CallbackHandler callbackHandler,
        String serviceName,
        byte[] ticket
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
                new Object[] {ex.getMessage()},
                ex
            );
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("Successfully authenticated to the TGT");
        }

        // Get the service name to use - fall back on the principal
        Subject subject = loginContext.getSubject();
        String service = serviceName;
        if (service == null) {
            Set<Principal> principals = subject.getPrincipals();
            if (principals.isEmpty()) {
                throw new WSSecurityException(
                    WSSecurityException.FAILURE, 
                    "kerberosLoginError", 
                    new Object[] {"No Client principals found after login"}
                );
            }
            service = principals.iterator().next().getName();
        }

        // Validate the ticket
        serviceAction.setTicket(ticket);
        serviceAction.setServiceName(service);
        token = (byte[])Subject.doAs(subject, serviceAction);
        
        secContext = serviceAction.getContext();
        if (LOG.isDebugEnabled()) {
            LOG.debug("Successfully validated a service ticket");
        }

    }
    
    /**
     * Whether to enable mutual authentication or not. This only applies to retrieve service ticket.
     */
    public void setMutualAuth(boolean mutualAuthentication) {
        mutualAuth = mutualAuthentication;
    }

    /**
     * Get the SPNEGO token that was created.
     */
    public byte[] getToken() {
        return token;
    }
    
    /**
     * Whether a connection has been established (at the service side)
     */
    public boolean isEstablished() {
        if (secContext == null) {
            return false;
        }
        return secContext.isEstablished();
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
                WSSecurityException.FAILURE, "spnegoKeyError", null, e
            );
        }
    }
    
    /**
     * Wrap a key
     */
    public byte[] wrapKey(byte[] secret) throws WSSecurityException {
        MessageProp mProp = new MessageProp(0, true);
        try {
            return secContext.wrap(secret, 0, secret.length, mProp);
        } catch (GSSException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Error in cleaning up a GSS context", e);
            }
            throw new WSSecurityException(
                WSSecurityException.FAILURE, "spnegoKeyError", null, e
            );
        }
    }
    
    /**
     * Set a custom SpnegoClientAction implementation to use
     */
    public void setSpnegoClientAction(SpnegoClientAction spnegoClientAction) {
        this.clientAction = spnegoClientAction;
    }
    
    /**
     * Set a custom SpnegoServiceAction implementation to use
     */
    public void setSpnegoServiceAction(SpnegoServiceAction spnegoServiceAction) {
        this.serviceAction = spnegoServiceAction;
    }
    
    public void clear() {
        token = null;
        mutualAuth = false;
        try {
            secContext.dispose();
        } catch (GSSException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Error in cleaning up a GSS context", e);
            }
        }
    }
    
}
