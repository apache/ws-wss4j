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
package org.apache.wss4j.stax.validate;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import org.apache.wss4j.binding.wss10.EncodedString;
import org.apache.wss4j.binding.wss10.PasswordString;
import org.apache.wss4j.binding.wss10.UsernameTokenType;
import org.apache.wss4j.binding.wsu10.AttributedDateTime;
import org.apache.wss4j.common.NamePasswordCallbackHandler;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.securityToken.UsernameSecurityToken;
import org.apache.wss4j.stax.securityToken.WSSecurityTokenConstants;
import org.apache.wss4j.stax.impl.securityToken.UsernameSecurityTokenImpl;
import org.apache.xml.security.stax.ext.XMLSecurityUtils;
import org.apache.xml.security.stax.securityToken.InboundSecurityToken;
import org.apache.xml.security.utils.XMLUtils;

/**
 * This class validates a processed UsernameToken, where Username/password validation is delegated
 * to the JAAS LoginContext.
 */
public class JAASUsernameTokenValidatorImpl implements UsernameTokenValidator {

    private static final transient org.slf4j.Logger LOG =
            org.slf4j.LoggerFactory.getLogger(JAASUsernameTokenValidatorImpl.class);

    private String contextName;

    public void setContextName(String name) {
        contextName = name;
    }

    public String getContextName() {
        return contextName;
    }

    @Override
    public <T extends UsernameSecurityToken & InboundSecurityToken> T validate(
            UsernameTokenType usernameTokenType, TokenContext tokenContext) throws WSSecurityException {

        PasswordString passwordType = XMLSecurityUtils.getQNameType(usernameTokenType.getAny(), WSSConstants.TAG_WSSE_PASSWORD);
        WSSConstants.UsernameTokenPasswordType usernameTokenPasswordType = WSSConstants.UsernameTokenPasswordType.PASSWORD_NONE;
        if (passwordType != null && passwordType.getType() != null) {
            usernameTokenPasswordType = WSSConstants.UsernameTokenPasswordType.getUsernameTokenPasswordType(passwordType.getType());
        }

        // Digest not supported
        if (usernameTokenPasswordType != WSSConstants.UsernameTokenPasswordType.PASSWORD_TEXT) {
            LOG.warn("Password type is not supported");
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_AUTHENTICATION);
        }

        String username = null;
        if (usernameTokenType.getUsername() != null) {
            username = usernameTokenType.getUsername().getValue();
        }
        String password = null;
        if (passwordType != null) {
            password = passwordType.getValue();
        }

        if (username == null || username.isEmpty() || password == null || password.isEmpty()) {
            LOG.warn("User or password empty");
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_AUTHENTICATION);
        }

        Subject subject;
        try {
            CallbackHandler handler = getCallbackHandler(username, password);
            LoginContext ctx = new LoginContext(getContextName(), handler);
            ctx.login();
            subject = ctx.getSubject();
        } catch (LoginException ex) {
            LOG.info("Authentication failed", ex);
            throw new WSSecurityException(
                WSSecurityException.ErrorCode.FAILED_AUTHENTICATION, ex
            );
        }

        final EncodedString encodedNonce =
                XMLSecurityUtils.getQNameType(usernameTokenType.getAny(), WSSConstants.TAG_WSSE_NONCE);
        byte[] nonceVal = null;
        if (encodedNonce != null) {
            if (!WSSConstants.SOAPMESSAGE_NS10_BASE64_ENCODING.equals(encodedNonce.getEncodingType())) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.UNSUPPORTED_SECURITY_TOKEN, "badTokenType01");
            }
            nonceVal = XMLUtils.decode(encodedNonce.getValue());
        }

        final AttributedDateTime attributedDateTimeCreated =
                XMLSecurityUtils.getQNameType(usernameTokenType.getAny(), WSSConstants.TAG_WSU_CREATED);

        UsernameSecurityTokenImpl usernameSecurityToken = new UsernameSecurityTokenImpl(
                usernameTokenPasswordType, username, password,
                attributedDateTimeCreated != null ? attributedDateTimeCreated.getValue() : null,
                nonceVal, null, null,
                tokenContext.getWsSecurityContext(), usernameTokenType.getId(),
                WSSecurityTokenConstants.KEYIDENTIFIER_SECURITY_TOKEN_DIRECT_REFERENCE);
        usernameSecurityToken.setElementPath(tokenContext.getElementPath());
        usernameSecurityToken.setXMLSecEvent(tokenContext.getFirstXMLSecEvent());
        usernameSecurityToken.setSubject(subject);

        @SuppressWarnings("unchecked")
        T token = (T)usernameSecurityToken;
        return token;
    }

    protected CallbackHandler getCallbackHandler(String name, String password) {
        return new NamePasswordCallbackHandler(name, password);
    }
}
