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

import java.security.Key;
import java.security.Principal;
import java.security.PrivilegedActionException;
import java.util.Set;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.kerberos.KerberosTicket;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSecurityException;
import org.ietf.jgss.GSSCredential;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * Kerberos Security Token.
 */
public class KerberosSecurity extends BinarySecurity {
    private static org.apache.commons.logging.Log log =
        org.apache.commons.logging.LogFactory.getLog(KerberosSecurity.class);
    private SecretKey secretKey;

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
        String valueType = getValueType();
        if (bspCompliant && !WSConstants.WSS_GSS_KRB_V5_AP_REQ.equals(valueType)) {
            throw new WSSecurityException(
                WSSecurityException.INVALID_SECURITY_TOKEN, 
                "invalidValueType", 
                new Object[]{valueType}
            );
        }
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
        retrieveServiceTicket(jaasLoginModuleName, callbackHandler, serviceName, false);
    }

    public void retrieveServiceTicket(
        String jaasLoginModuleName, 
        CallbackHandler callbackHandler,
        String serviceName,
        boolean isUsernameServiceNameForm
    ) throws WSSecurityException {
        retrieveServiceTicket(jaasLoginModuleName, callbackHandler, serviceName, 
                              isUsernameServiceNameForm, false);
    }
    
    public void retrieveServiceTicket(
         String jaasLoginModuleName, 
         CallbackHandler callbackHandler,
         String serviceName,
         boolean isUsernameServiceNameForm,
         boolean requestCredDeleg
    ) throws WSSecurityException {
        retrieveServiceTicket(jaasLoginModuleName, callbackHandler, serviceName, 
                              isUsernameServiceNameForm, requestCredDeleg, null);
    }
    
    public void retrieveServiceTicket(
        String jaasLoginModuleName, 
        CallbackHandler callbackHandler,
        String serviceName,
        boolean isUsernameServiceNameForm,
        boolean requestCredDeleg,
        GSSCredential delegatedCredential
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
                new Object[] {ex.getMessage()},
                ex
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
        // Store the TGT
        KerberosTicket tgt = getKerberosTicket(clientSubject, null);

        // Get the service ticket
        KerberosClientExceptionAction action = 
            new KerberosClientExceptionAction(clientPrincipals.iterator().next(), serviceName, 
                                              isUsernameServiceNameForm, requestCredDeleg,
                                              delegatedCredential);
        KerberosContext krbCtx = null;
        try {
            krbCtx = (KerberosContext) Subject.doAs(clientSubject, action);

            // Get the secret key from KerberosContext if available, otherwise use Kerberos ticket's session key
            Key sessionKey = krbCtx.getSecretKey();
            if (sessionKey != null) {
                secretKey = new SecretKeySpec(sessionKey.getEncoded(), sessionKey.getAlgorithm());
            } else {
                KerberosTicket serviceTicket = getKerberosTicket(clientSubject, tgt);
                secretKey = serviceTicket.getSessionKey();
            }

            setToken(krbCtx.getKerberosToken());
        }
        catch (PrivilegedActionException e) {
            Throwable cause = e.getCause();
            if (cause instanceof WSSecurityException) {
                throw (WSSecurityException) cause;
            }
            else {
                throw new WSSecurityException(
                     WSSecurityException.FAILURE, "kerberosServiceTicketError", new Object[] {}, cause
                );
            }
        } finally {
            if (krbCtx != null) {
                krbCtx.dispose();
            }
        }
        if (log.isDebugEnabled()) {
            log.debug("Successfully retrieved a service ticket");
        }

        if ("".equals(getValueType())) {
            setValueType(WSConstants.WSS_GSS_KRB_V5_AP_REQ);
        }
    }



    /**
     * Get a KerberosTicket from the clientSubject parameter, that is not equal to the supplied KerberosTicket
     * parameter (can be null)
     */
    private KerberosTicket getKerberosTicket(Subject clientSubject, KerberosTicket previousTicket) {
        Set<KerberosTicket> privateCredentials = clientSubject.getPrivateCredentials(KerberosTicket.class);
        if (privateCredentials == null || privateCredentials.isEmpty()) {
            if (log.isDebugEnabled()) {
                log.debug("Kerberos client subject private credentials are null");
            }
            return null;
        }

        for (KerberosTicket privateCredential : privateCredentials) {
            if (!privateCredential.equals(previousTicket)) {
                return privateCredential;
            }
        }
        return null;
    }

    /**
     * Get the SecretKey associated with the service principal
     * @return the SecretKey associated with the service principal
     */
    public SecretKey getSecretKey() {
        return secretKey;
    }

    /**
     * Return true if the valueType represents a Kerberos Token
     * @param valueType the valueType of the token
     * @return true if the valueType represents a Kerberos Token
     */
    public static boolean isKerberosToken(String valueType) {
        if (WSConstants.WSS_KRB_V5_AP_REQ.equals(valueType)
            || WSConstants.WSS_GSS_KRB_V5_AP_REQ.equals(valueType)
            || WSConstants.WSS_KRB_V5_AP_REQ1510.equals(valueType)
            || WSConstants.WSS_GSS_KRB_V5_AP_REQ1510.equals(valueType)
            || WSConstants.WSS_KRB_V5_AP_REQ4120.equals(valueType)
            || WSConstants.WSS_GSS_KRB_V5_AP_REQ4120.equals(valueType)) {
            return true;
        }
        return false;
    }

}