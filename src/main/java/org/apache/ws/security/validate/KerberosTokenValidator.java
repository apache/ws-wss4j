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

package org.apache.ws.security.validate;

import java.security.Principal;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.handler.RequestData;
import org.apache.ws.security.message.token.BinarySecurity;
import org.apache.ws.security.message.token.KerberosSecurity;
import org.apache.ws.security.message.token.KerberosServiceAction;

/**
 */
public class KerberosTokenValidator implements Validator {
    
    private static org.apache.commons.logging.Log log =
        org.apache.commons.logging.LogFactory.getLog(KerberosTokenValidator.class);
    
    private String serviceName;
    private CallbackHandler callbackHandler;
    private String contextName;
    private KerberosTokenDecoder kerberosTokenDecoder;
    
    /**
     * Get the JAAS Login context name to use.
     * @return the JAAS Login context name to use
     */
    public String getContextName() {
        return contextName;
    }

    /**
     * Set the JAAS Login context name to use.
     * @param contextName the JAAS Login context name to use
     */
    public void setContextName(String contextName) {
        this.contextName = contextName;
    }
    
    /**
     * @deprecated
     * Get the JAAS Login module name to use.
     * @return the JAAS Login module name to use
     */
    public String getJaasLoginModuleName() {
        return contextName;
    }

    /**
     * @deprecated
     * Set the JAAS Login module name to use.
     * @param jaasLoginModuleName the JAAS Login module name to use
     */
    public void setJaasLoginModuleName(String jaasLoginModuleName) {
        this.contextName = jaasLoginModuleName;
    }

    /**
     * Get the CallbackHandler to use with the LoginContext
     * @return the CallbackHandler to use with the LoginContext
     */
    public CallbackHandler getCallbackHandler() {
        return callbackHandler;
    }

    /**
     * Set the CallbackHandler to use with the LoginContext. It can be null.
     * @param callbackHandler the CallbackHandler to use with the LoginContext
     */
    public void setCallbackHandler(CallbackHandler callbackHandler) {
        this.callbackHandler = callbackHandler;
    }

    /**
     * The name of the service to use when contacting the KDC. This value can be null, in which
     * case it defaults to the current principal name.
     * @param serviceName the name of the service to use when contacting the KDC
     */
    public void setServiceName(String serviceName) {
        this.serviceName = serviceName;
    }
    
    /**
     * Get the name of the service to use when contacting the KDC. This value can be null, in which
     * case it defaults to the current principal name.
     * @return the name of the service to use when contacting the KDC
     */
    public String getServiceName() {
        return serviceName;
    }
    
    /**
     * Get the KerberosTokenDecoder instance used to extract a session key from the received Kerberos
     * token.
     * @return the KerberosTokenDecoder instance used to extract a session key
     */
    public KerberosTokenDecoder getKerberosTokenDecoder() {
        return kerberosTokenDecoder;
    }

    /**
     * Set the KerberosTokenDecoder instance used to extract a session key from the received Kerberos
     * token.
     * @param kerberosTokenDecoder the KerberosTokenDecoder instance used to extract a session key
     */
    public void setKerberosTokenDecoder(KerberosTokenDecoder kerberosTokenDecoder) {
        this.kerberosTokenDecoder = kerberosTokenDecoder;
    }
    
    /**
     * Validate the credential argument. It must contain a non-null BinarySecurityToken. 
     * 
     * @param credential the Credential to be validated
     * @param data the RequestData associated with the request
     * @throws WSSecurityException on a failed validation
     */
    public Credential validate(Credential credential, RequestData data) throws WSSecurityException {
        if (credential == null || credential.getBinarySecurityToken() == null) {
            throw new WSSecurityException(WSSecurityException.FAILURE, "noCredential");
        }
        
        BinarySecurity binarySecurity = credential.getBinarySecurityToken();
        if (!(binarySecurity instanceof KerberosSecurity)) {
            return credential;
        }
        
        if (log.isDebugEnabled()) {
            try {
                String jaasAuth = System.getProperty("java.security.auth.login.config");
                String krbConf = System.getProperty("java.security.krb5.conf");
                log.debug("KerberosTokenValidator - Using JAAS auth login file: " + jaasAuth);
                log.debug("KerberosTokenValidator - Using KRB conf file: " + krbConf);
            } catch (SecurityException ex) {
                log.debug(ex.getMessage(), ex);
            }
        }
        
        // Get a TGT from the KDC using JAAS
        LoginContext loginContext = null;
        try {
            if (callbackHandler == null) {
                loginContext = new LoginContext(getContextName());
            } else {
                loginContext = new LoginContext(getContextName(), callbackHandler);
            }
            loginContext.login();
        } catch (LoginException ex) {
            if (log.isDebugEnabled()) {
                log.debug(ex.getMessage(), ex);
            }
            throw new WSSecurityException(
                WSSecurityException.FAILURE,
                "kerberosLoginError", 
                new Object[] {ex.getMessage()},
                ex
            );
        }
        if (log.isDebugEnabled()) {
            log.debug("Successfully authenticated to the TGT");
        }
        
        byte[] token = binarySecurity.getToken();
        
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
        KerberosServiceAction action = new KerberosServiceAction(token, service);
        Principal principal = (Principal)Subject.doAs(subject, action);
        if (principal == null) {
            throw new WSSecurityException(
                WSSecurityException.FAILURE, "kerberosTicketValidationError"
            );
        }
        credential.setPrincipal(principal);
        credential.setSubject(subject);
        
        // Try to extract the session key from the token if a KerberosTokenDecoder implementation is
        // available
        if (kerberosTokenDecoder != null) {
            kerberosTokenDecoder.clear();
            kerberosTokenDecoder.setToken(token);
            kerberosTokenDecoder.setSubject(subject);
            byte[] sessionKey = kerberosTokenDecoder.getSessionKey();
            credential.setSecretKey(sessionKey);
        }
        
        if (log.isDebugEnabled()) {
            log.debug("Successfully validated a ticket");
        }
        
        return credential;
    }
    
}
