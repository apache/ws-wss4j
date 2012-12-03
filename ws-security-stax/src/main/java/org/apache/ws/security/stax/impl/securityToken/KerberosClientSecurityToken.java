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
package org.apache.ws.security.stax.impl.securityToken;

import org.apache.ws.security.common.ext.WSSecurityException;
import org.apache.ws.security.common.kerberos.KerberosClientAction;
import org.apache.ws.security.common.kerberos.KerberosContextAndServiceNameCallback;
import org.apache.ws.security.stax.ext.WSSConstants;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.config.JCEAlgorithmMapper;
import org.apache.xml.security.stax.impl.securityToken.GenericOutboundSecurityToken;

import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.kerberos.KerberosTicket;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import java.io.IOException;
import java.security.Key;
import java.security.Principal;
import java.util.Set;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class KerberosClientSecurityToken extends GenericOutboundSecurityToken {

    private CallbackHandler callbackHandler;
    private Key secretKey;
    private byte[] ticket;

    public KerberosClientSecurityToken(CallbackHandler callbackHandler, String id) throws XMLSecurityException {
        super(id, WSSConstants.KerberosToken);
        this.callbackHandler = callbackHandler;
    }

    private void getTGT() throws WSSecurityException {
        try {
            KerberosContextAndServiceNameCallback contextAndServiceNameCallback = new KerberosContextAndServiceNameCallback();
            callbackHandler.handle(new Callback[]{contextAndServiceNameCallback});

            if (contextAndServiceNameCallback.getContextName() == null) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "kerberosCallbackContextNameNotSupplied");
            }
            if (contextAndServiceNameCallback.getServiceName() == null) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "kerberosCallbackServiceNameNotSupplied");
            }

            LoginContext loginContext = new LoginContext(contextAndServiceNameCallback.getContextName(), callbackHandler);
            loginContext.login();

            Subject clientSubject = loginContext.getSubject();
            Set<Principal> clientPrincipals = clientSubject.getPrincipals();
            if (clientPrincipals.isEmpty()) {
                throw new WSSecurityException(
                        WSSecurityException.ErrorCode.FAILURE,
                        "kerberosLoginError", "No Client principals found after login"
                );
            }
            // Store the TGT
            KerberosTicket tgt = getKerberosTicket(clientSubject, null);

            // Get the service ticket
            KerberosClientAction action =
                    new KerberosClientAction(
                            clientPrincipals.iterator().next(), contextAndServiceNameCallback.getServiceName()
                    );
            byte[] ticket = Subject.doAs(clientSubject, action);
            if (ticket == null) {
                throw new WSSecurityException(
                        WSSecurityException.ErrorCode.FAILURE, "kerberosServiceTicketError"
                );
            }

            // Get the Service Ticket (private credential)
            KerberosTicket serviceTicket = getKerberosTicket(clientSubject, tgt);
            if (serviceTicket != null) {
                this.secretKey = serviceTicket.getSessionKey();
            }

            this.ticket = ticket;

        } catch (LoginException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, e);
        } catch (UnsupportedCallbackException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, e);
        } catch (IOException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, e);
        }
    }

    /**
     * Get a KerberosTicket from the clientSubject parameter, that is not equal to the supplied KerberosTicket
     * parameter (can be null)
     */
    private KerberosTicket getKerberosTicket(Subject clientSubject, KerberosTicket previousTicket) {
        Set<KerberosTicket> privateCredentials = clientSubject.getPrivateCredentials(KerberosTicket.class);
        if (privateCredentials == null || privateCredentials.isEmpty()) {
            return null;
        }

        for (KerberosTicket privateCredential : privateCredentials) {
            if (!privateCredential.equals(previousTicket)) {
                return privateCredential;
            }
        }
        return null;
    }

    @Override
    public Key getSecretKey(String algorithmURI) throws XMLSecurityException {
        Key key = super.getSecretKey(algorithmURI);
        if (key != null) {
            return key;
        }
        if (this.secretKey == null) {
            getTGT();
        }
        String algoFamily = JCEAlgorithmMapper.getJCERequiredKeyFromURI(algorithmURI);
        key = new SecretKeySpec(this.secretKey.getEncoded(), algoFamily);
        setSecretKey(algorithmURI, key);
        return key;
    }

    public byte[] getTicket() throws XMLSecurityException {
        if (this.ticket == null) {
            getTGT();
        }
        return ticket;
    }
}
