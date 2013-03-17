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
import org.apache.wss4j.stax.ext.InboundSecurityToken;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.ext.WSSUtils;
import org.apache.wss4j.stax.impl.securityToken.UsernameSecurityToken;
import org.apache.xml.security.stax.ext.XMLSecurityUtils;

public class UsernameTokenValidatorImpl implements UsernameTokenValidator {

    @Override
    public InboundSecurityToken validate(UsernameTokenType usernameTokenType, TokenContext tokenContext) throws WSSecurityException {

        // If the UsernameToken is to be used for key derivation, the (1.1)
        // spec says that it cannot contain a password, and it must contain
        // an Iteration element
        final byte[] salt = XMLSecurityUtils.getQNameType(usernameTokenType.getAny(), WSSConstants.TAG_wsse11_Salt);
        PasswordString passwordType = XMLSecurityUtils.getQNameType(usernameTokenType.getAny(), WSSConstants.TAG_wsse_Password);
        final Long iteration = XMLSecurityUtils.getQNameType(usernameTokenType.getAny(), WSSConstants.TAG_wsse11_Iteration);
        if (salt != null && (passwordType != null || iteration == null)) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY_TOKEN, "badTokenType01");
        }

        boolean handleCustomPasswordTypes = tokenContext.getWssSecurityProperties().getHandleCustomPasswordTypes();
        boolean allowUsernameTokenNoPassword = 
            tokenContext.getWssSecurityProperties().isAllowUsernameTokenNoPassword() 
                || Boolean.parseBoolean((String)tokenContext.getWsSecurityContext().get(WSSConstants.PROP_ALLOW_USERNAMETOKEN_NOPASSWORD));

        final byte[] nonceVal;

        WSSConstants.UsernameTokenPasswordType usernameTokenPasswordType = WSSConstants.UsernameTokenPasswordType.PASSWORD_NONE;
        if (passwordType != null && passwordType.getType() != null) {
            usernameTokenPasswordType = WSSConstants.UsernameTokenPasswordType.getUsernameTokenPasswordType(passwordType.getType());
        }

        final AttributedString username = usernameTokenType.getUsername();
        if (username == null) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY_TOKEN, "badTokenType01");
        }

        final EncodedString encodedNonce =
                XMLSecurityUtils.getQNameType(usernameTokenType.getAny(), WSSConstants.TAG_wsse_Nonce);

        final AttributedDateTime attributedDateTimeCreated =
                XMLSecurityUtils.getQNameType(usernameTokenType.getAny(), WSSConstants.TAG_wsu_Created);
        final String created;
        if (attributedDateTimeCreated != null) {
            created = attributedDateTimeCreated.getValue();
        } else {
            created = null;
        }

        if (usernameTokenPasswordType == WSSConstants.UsernameTokenPasswordType.PASSWORD_DIGEST) {
            if (encodedNonce == null || attributedDateTimeCreated == null) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY_TOKEN, "badTokenType01");
            }

            if (!WSSConstants.SOAPMESSAGE_NS10_BASE64_ENCODING.equals(encodedNonce.getEncodingType())) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.UNSUPPORTED_SECURITY_TOKEN, "badTokenType01");
            }

            nonceVal = Base64.decodeBase64(encodedNonce.getValue());

            verifyDigestPassword(username.getValue(), passwordType, nonceVal, created, tokenContext);
        } else if ((usernameTokenPasswordType == WSSConstants.UsernameTokenPasswordType.PASSWORD_TEXT)
                || (passwordType != null && passwordType.getValue() != null
                && usernameTokenPasswordType == WSSConstants.UsernameTokenPasswordType.PASSWORD_NONE)) {
            nonceVal = null;
            
            verifyPlaintextPassword(username.getValue(), passwordType, tokenContext);
        } else if (passwordType != null && passwordType.getValue() != null) {
            if (!handleCustomPasswordTypes) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_AUTHENTICATION);
            }
            nonceVal = null;
            
            verifyCustomPassword(username.getValue(), passwordType, tokenContext);
        } else {
            if (!allowUsernameTokenNoPassword) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_AUTHENTICATION);
            }
            nonceVal = null;
        }

        final String password;
        if (passwordType != null) {
            password = passwordType.getValue();
        } else {
            password = null;
        }

        UsernameSecurityToken usernameSecurityToken = new UsernameSecurityToken(
                username.getValue(), password, created, nonceVal, salt, iteration,
                tokenContext.getWsSecurityContext(), usernameTokenType.getId(),
                WSSConstants.WSSKeyIdentifierType.SECURITY_TOKEN_DIRECT_REFERENCE);
        usernameSecurityToken.setElementPath(tokenContext.getElementPath());
        usernameSecurityToken.setXMLSecEvent(tokenContext.getFirstXMLSecEvent());

        return usernameSecurityToken;
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
                WSPasswordCallback.Usage.USERNAME_TOKEN);
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
                WSPasswordCallback.Usage.USERNAME_TOKEN);
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
