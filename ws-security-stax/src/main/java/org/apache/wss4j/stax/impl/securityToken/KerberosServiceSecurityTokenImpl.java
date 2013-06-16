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

import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.kerberos.*;
import org.apache.wss4j.stax.ext.WSInboundSecurityContext;
import org.apache.wss4j.stax.securityToken.KerberosServiceSecurityToken;
import org.apache.wss4j.stax.securityToken.WSSecurityTokenConstants;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.config.JCEAlgorithmMapper;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.impl.securityToken.AbstractInboundSecurityToken;

import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import java.io.IOException;
import java.security.Key;
import java.security.Principal;
import java.util.Set;

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
        return WSSecurityTokenConstants.KerberosToken;
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
                            "No Client principals found after login"
                    );
                }
                service = principals.iterator().next().getName();
            }

            // Validate the ticket
            KerberosServiceAction action = new KerberosServiceAction(binaryContent, service);
            this.principal = Subject.doAs(subject, action);
            if (this.principal == null) {
                throw new WSSecurityException(
                        WSSecurityException.ErrorCode.FAILURE, "kerberosTicketValidationError"
                );
            }

            KerberosTokenDecoder kerberosTokenDecoder = new KerberosTokenDecoderImpl();
            kerberosTokenDecoder.setToken(binaryContent);
            kerberosTokenDecoder.setSubject(subject);
            return kerberosTokenDecoder;

        } catch (LoginException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, e);
        } catch (UnsupportedCallbackException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, e);
        } catch (IOException e) {
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

        String algoFamily = JCEAlgorithmMapper.getJCEKeyAlgorithmFromURI(algorithmURI);
        int keyLength = JCEAlgorithmMapper.getKeyLengthFromURI(algorithmURI) / 8;
        if (sk.length < keyLength) {
            //normally we should throw an exception here because we don't have
            //enough key material for the requested algorithm
            //but I haven't found any documentation about how this case should be handled
            //and the second thing is that we would need a kerberos key with minimum 160 bits
            //to be able to sign with a more or less secure algo like hmacsha1
            keyLength = sk.length;
        }

        key = new SecretKeySpec(sk, 0, keyLength, algoFamily);
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
}
