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

import org.apache.commons.codec.binary.Base64;
import org.apache.wss4j.binding.wss10.AttributedString;
import org.apache.wss4j.binding.wss10.EncodedString;
import org.apache.wss4j.binding.wss10.PasswordString;
import org.apache.wss4j.binding.wss10.UsernameTokenType;
import org.apache.wss4j.binding.wsu10.AttributedDateTime;
import org.apache.wss4j.common.ext.WSPasswordCallback;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.securityToken.UsernameSecurityToken;
import org.apache.wss4j.stax.securityToken.WSSecurityTokenConstants;
import org.apache.wss4j.stax.utils.WSSUtils;
import org.apache.wss4j.stax.impl.securityToken.UsernameSecurityTokenImpl;
import org.apache.xml.security.stax.ext.XMLSecurityUtils;
import org.apache.xml.security.stax.securityToken.InboundSecurityToken;

public class UsernameTokenValidatorImpl implements UsernameTokenValidator {

    private static final transient org.slf4j.Logger LOG = org.slf4j.LoggerFactory.getLogger(UsernameTokenValidatorImpl.class);

    @Override
    public <T extends UsernameSecurityToken & InboundSecurityToken> T validate(
            UsernameTokenType usernameTokenType, TokenContext tokenContext) throws WSSecurityException {

        // If the UsernameToken is to be used for key derivation, the (1.1)
        // spec says that it cannot contain a password, and it must contain
        // an Iteration element
        final byte[] salt = XMLSecurityUtils.getQNameType(usernameTokenType.getAny(), WSSConstants.TAG_WSSE11_SALT);
        PasswordString passwordType = XMLSecurityUtils.getQNameType(usernameTokenType.getAny(), WSSConstants.TAG_WSSE_PASSWORD);
        final Long iteration = XMLSecurityUtils.getQNameType(usernameTokenType.getAny(), WSSConstants.TAG_WSSE11_ITERATION);
        if (salt != null && (passwordType != null || iteration == null)) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY_TOKEN, "badTokenType01");
        }

        boolean handleCustomPasswordTypes = tokenContext.getWssSecurityProperties().getHandleCustomPasswordTypes();
        boolean allowUsernameTokenNoPassword =
            tokenContext.getWssSecurityProperties().isAllowUsernameTokenNoPassword()
                || Boolean.parseBoolean((String)tokenContext.getWsSecurityContext().get(WSSConstants.PROP_ALLOW_USERNAMETOKEN_NOPASSWORD));

        // Check received password type against required type
        WSSConstants.UsernameTokenPasswordType requiredPasswordType =
            tokenContext.getWssSecurityProperties().getUsernameTokenPasswordType();
        if (requiredPasswordType != null) {
            if (passwordType == null || passwordType.getType() == null) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Authentication failed as the received password type does not "
                        + "match the required password type of: " + requiredPasswordType);
                }
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_AUTHENTICATION);
            }
            WSSConstants.UsernameTokenPasswordType usernameTokenPasswordType =
                WSSConstants.UsernameTokenPasswordType.getUsernameTokenPasswordType(passwordType.getType());
            if (requiredPasswordType != usernameTokenPasswordType) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Authentication failed as the received password type does not "
                        + "match the required password type of: " + requiredPasswordType);
                }
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_AUTHENTICATION);
            }
        }

        WSSConstants.UsernameTokenPasswordType usernameTokenPasswordType = WSSConstants.UsernameTokenPasswordType.PASSWORD_NONE;
        if (passwordType != null && passwordType.getType() != null) {
            usernameTokenPasswordType = WSSConstants.UsernameTokenPasswordType.getUsernameTokenPasswordType(passwordType.getType());
        }

        final AttributedString username = usernameTokenType.getUsername();
        if (username == null) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY_TOKEN, "badTokenType01");
        }

        final EncodedString encodedNonce =
                XMLSecurityUtils.getQNameType(usernameTokenType.getAny(), WSSConstants.TAG_WSSE_NONCE);
        byte[] nonceVal = null;
        if (encodedNonce != null && encodedNonce.getValue() != null) {
            nonceVal = Base64.decodeBase64(encodedNonce.getValue());
        }

        final AttributedDateTime attributedDateTimeCreated =
                XMLSecurityUtils.getQNameType(usernameTokenType.getAny(), WSSConstants.TAG_WSU_CREATED);

        String created = null;
        if (attributedDateTimeCreated != null) {
            created = attributedDateTimeCreated.getValue();
        }

        if (usernameTokenPasswordType == WSSConstants.UsernameTokenPasswordType.PASSWORD_DIGEST) {
            if (encodedNonce == null || attributedDateTimeCreated == null) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY_TOKEN, "badTokenType01");
            }

            if (!WSSConstants.SOAPMESSAGE_NS10_BASE64_ENCODING.equals(encodedNonce.getEncodingType())) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.UNSUPPORTED_SECURITY_TOKEN, "badTokenType01");
            }

            verifyDigestPassword(username.getValue(), passwordType, nonceVal, created, tokenContext);
        } else if (usernameTokenPasswordType == WSSConstants.UsernameTokenPasswordType.PASSWORD_TEXT
                || passwordType != null && passwordType.getValue() != null
                && usernameTokenPasswordType == WSSConstants.UsernameTokenPasswordType.PASSWORD_NONE) {

            verifyPlaintextPassword(username.getValue(), passwordType, tokenContext);
        } else if (passwordType != null && passwordType.getValue() != null) {
            if (!handleCustomPasswordTypes) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_AUTHENTICATION);
            }
            verifyCustomPassword(username.getValue(), passwordType, tokenContext);
        } else {
            if (!allowUsernameTokenNoPassword) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_AUTHENTICATION);
            }
        }

        final String password;
        if (passwordType != null) {
            password = passwordType.getValue();
        } else if (salt != null) {
            WSPasswordCallback pwCb = new WSPasswordCallback(username.getValue(),
                   WSPasswordCallback.USERNAME_TOKEN);
            try {
                WSSUtils.doPasswordCallback(tokenContext.getWssSecurityProperties().getCallbackHandler(), pwCb);
            } catch (WSSecurityException e) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_AUTHENTICATION, e);
            }
            password = pwCb.getPassword();
        } else {
            password = null;
        }

        UsernameSecurityTokenImpl usernameSecurityToken = new UsernameSecurityTokenImpl(
                usernameTokenPasswordType, username.getValue(), password, created,
                nonceVal, salt, iteration,
                tokenContext.getWsSecurityContext(), usernameTokenType.getId(),
                WSSecurityTokenConstants.KeyIdentifier_SecurityTokenDirectReference);
        usernameSecurityToken.setElementPath(tokenContext.getElementPath());
        usernameSecurityToken.setXMLSecEvent(tokenContext.getFirstXMLSecEvent());

        @SuppressWarnings("unchecked")
        T token = (T)usernameSecurityToken;
        return token;
    }

    /**
     * Verify a UsernameToken containing a password digest.
     */
    protected void verifyDigestPassword(
        String username,
        PasswordString passwordType,
        byte[] nonceVal,
        String created,
        TokenContext tokenContext
    ) throws WSSecurityException {
        WSPasswordCallback pwCb = new WSPasswordCallback(username,
                null,
                passwordType.getType(),
                WSPasswordCallback.USERNAME_TOKEN);
        try {
            WSSUtils.doPasswordCallback(tokenContext.getWssSecurityProperties().getCallbackHandler(), pwCb);
        } catch (WSSecurityException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_AUTHENTICATION, e);
        }

        if (pwCb.getPassword() == null) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_AUTHENTICATION);
        }

        String passDigest = WSSUtils.doPasswordDigest(nonceVal, created, pwCb.getPassword());
        if (!passwordType.getValue().equals(passDigest)) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_AUTHENTICATION);
        }
        passwordType.setValue(pwCb.getPassword());
    }

    /**
     * Verify a UsernameToken containing a plaintext password.
     */
    protected void verifyPlaintextPassword(
        String username,
        PasswordString passwordType,
        TokenContext tokenContext
    ) throws WSSecurityException {
        WSPasswordCallback pwCb = new WSPasswordCallback(username,
                null,
                passwordType.getType(),
                WSPasswordCallback.USERNAME_TOKEN);
        try {
            WSSUtils.doPasswordCallback(tokenContext.getWssSecurityProperties().getCallbackHandler(), pwCb);
        } catch (WSSecurityException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_AUTHENTICATION, e);
        }

        if (pwCb.getPassword() == null) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_AUTHENTICATION);
        }

        if (!passwordType.getValue().equals(pwCb.getPassword())) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_AUTHENTICATION);
        }
        passwordType.setValue(pwCb.getPassword());
    }

    /**
     * Verify a UsernameToken containing a password of some unknown (but specified) password
     * type.
     */
    protected void verifyCustomPassword(
        String username,
        PasswordString passwordType,
        TokenContext tokenContext
    ) throws WSSecurityException {
        verifyPlaintextPassword(username, passwordType, tokenContext);
    }
}
