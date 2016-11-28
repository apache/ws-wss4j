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
package org.apache.wss4j.stax.impl.securityToken;

import java.io.IOException;
import java.security.Key;
import java.security.Principal;
import java.security.PrivilegedActionException;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.ext.WSSecurityException.ErrorCode;
import org.apache.wss4j.common.kerberos.KerberosContextAndServiceNameCallback;
import org.apache.wss4j.common.kerberos.KerberosServiceContext;
import org.apache.wss4j.common.kerberos.KerberosServiceExceptionAction;
import org.apache.wss4j.common.kerberos.KerberosTokenDecoder;
import org.apache.wss4j.common.kerberos.KerberosTokenDecoderException;
import org.apache.wss4j.common.kerberos.KerberosTokenDecoderImpl;
import org.apache.wss4j.common.util.KeyUtils;
import org.apache.wss4j.stax.ext.WSInboundSecurityContext;
import org.apache.wss4j.stax.securityToken.KerberosServiceSecurityToken;
import org.apache.wss4j.stax.securityToken.WSSecurityTokenConstants;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.impl.securityToken.AbstractInboundSecurityToken;

public class KerberosServiceSecurityTokenImpl extends AbstractInboundSecurityToken implements KerberosServiceSecurityToken {

    private CallbackHandler callbackHandler;
    private byte[] binaryContent;
    private String kerberosTokenValueType;

    private KerberosTokenDecoder kerberosTokenDecoder;
    private Subject subject;
    private Principal principal;

    public KerberosServiceSecurityTokenImpl(WSInboundSecurityContext wsInboundSecurityContext, CallbackHandler callbackHandler,
                                            byte[] binaryContent, String kerberosTokenValueType, String id,
                                            WSSecurityTokenConstants.KeyIdentifier keyIdentifier) {
        super(wsInboundSecurityContext, id, keyIdentifier, true);
        this.callbackHandler = callbackHandler;
        this.binaryContent = binaryContent;
        this.kerberosTokenValueType = kerberosTokenValueType;
    }

    @Override
    public boolean isAsymmetric() throws XMLSecurityException {
        return false;
    }

    @Override
    public WSSecurityTokenConstants.TokenType getTokenType() {
        return WSSecurityTokenConstants.KERBEROS_TOKEN;
    }

    protected KerberosTokenDecoder getTGT() throws WSSecurityException {
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

            // Get the service name to use - fall back on the principal
            this.subject = loginContext.getSubject();

            String service = contextAndServiceNameCallback.getServiceName();
            if (service == null) {
                Set<Principal> principals = subject.getPrincipals();
                if (principals.isEmpty()) {
                    throw new WSSecurityException(
                        WSSecurityException.ErrorCode.FAILURE,
                        "kerberosLoginError",
                        new Object[] {"No Client principals found after login"}
                    );
                }
                service = principals.iterator().next().getName();
            }

            KerberosServiceExceptionAction action =
                new KerberosServiceExceptionAction(binaryContent,
                                                   service,
                                                   contextAndServiceNameCallback.isUsernameServiceNameForm(),
                                                   false);
            KerberosServiceContext krbServiceCtx = null;
            try {
                krbServiceCtx = Subject.doAs(subject, action);
            } catch (PrivilegedActionException e) {
                Throwable cause = e.getCause();
                if (cause instanceof WSSecurityException) {
                    throw (WSSecurityException) cause;
                } else {
                    throw new WSSecurityException(
                        ErrorCode.FAILURE, new Exception(cause), "kerberosTicketValidationError"
                    );
                }
            }

            this.principal = krbServiceCtx.getPrincipal();

            final Key sessionKey = krbServiceCtx.getSessionKey();

            if (null != sessionKey) {
                return new KerberosTokenDecoder() {
                    public void setToken(byte[] token) { }
                    public void setSubject(Subject subject) { }
                    public byte[] getSessionKey() throws KerberosTokenDecoderException {
                        return sessionKey.getEncoded();
                    }
                    public void clear() { }
                };
            } else {
                KerberosTokenDecoder kerberosTokenDecoder = new KerberosTokenDecoderImpl();
                kerberosTokenDecoder.setToken(binaryContent);
                kerberosTokenDecoder.setSubject(subject);
                return kerberosTokenDecoder;
            }
        } catch (LoginException | UnsupportedCallbackException | IOException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, e);
        }
    }

    @Override
    protected Key getKey(String algorithmURI, XMLSecurityConstants.AlgorithmUsage algorithmUsage,
                         String correlationID) throws XMLSecurityException {

        Key key = getSecretKey().get(algorithmURI);
        if (key != null) {
            return key;
        }

        if (this.kerberosTokenDecoder == null) {
            this.kerberosTokenDecoder = getTGT();
        }

        byte[] sk;
        try {
            sk = this.kerberosTokenDecoder.getSessionKey();
        } catch (KerberosTokenDecoderException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY_TOKEN, e);
        }

        key = KeyUtils.prepareSecretKey(algorithmURI, sk);
        setSecretKey(algorithmURI, key);
        return key;
    }

    public byte[] getBinaryContent() {
        return binaryContent;
    }

    public String getKerberosTokenValueType() {
        return kerberosTokenValueType;
    }

    @Override
    public Subject getSubject() throws WSSecurityException {
        return subject;
    }

    @Override
    public Principal getPrincipal() throws WSSecurityException {
        return principal;
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
}
