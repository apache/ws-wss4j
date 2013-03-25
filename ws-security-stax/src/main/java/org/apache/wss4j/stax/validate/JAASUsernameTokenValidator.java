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

import java.io.UnsupportedEncodingException;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.wss4j.binding.wss10.AttributedString;
import org.apache.wss4j.binding.wss10.EncodedString;
import org.apache.wss4j.binding.wss10.PasswordString;
import org.apache.wss4j.binding.wss10.UsernameTokenType;
import org.apache.wss4j.binding.wsu10.AttributedDateTime;
import org.apache.wss4j.common.NamePasswordCallbackHandler;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.principal.WSUsernameTokenPrincipal;
import org.apache.wss4j.stax.ext.InboundSecurityToken;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.impl.securityToken.UsernameSecurityToken;
import org.apache.xml.security.stax.ext.XMLSecurityUtils;

/**
 * This class validates a processed UsernameToken, where Username/password validation is delegated
 * to the JAAS LoginContext.
 */
public class JAASUsernameTokenValidator implements UsernameTokenValidator {
    
    private static final transient Log log = LogFactory.getLog(JAASUsernameTokenValidator.class);
    
    private String contextName = null;
    
    public void setContextName(String name) {
        contextName = name;
    }
    
    public String getContextName() {
        return contextName;
    }

    @Override
    public InboundSecurityToken validate(UsernameTokenType usernameTokenType, TokenContext tokenContext) throws WSSecurityException {

        PasswordString passwordType = XMLSecurityUtils.getQNameType(usernameTokenType.getAny(), WSSConstants.TAG_wsse_Password);
        WSSConstants.UsernameTokenPasswordType usernameTokenPasswordType = WSSConstants.UsernameTokenPasswordType.PASSWORD_NONE;
        if (passwordType != null && passwordType.getType() != null) {
            usernameTokenPasswordType = WSSConstants.UsernameTokenPasswordType.getUsernameTokenPasswordType(passwordType.getType());
        }
        
        // Digest not supported
        if (usernameTokenPasswordType != WSSConstants.UsernameTokenPasswordType.PASSWORD_TEXT) {
            log.warn("Password type is not supported");
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_AUTHENTICATION);    
        }
        
        final AttributedString username = usernameTokenType.getUsername();
        String user = null;
        if (username != null) {
            user = username.getValue();
        }
        String password = null;
        if (passwordType != null) {
            password = passwordType.getValue();
        }
        
        if (!(user != null && user.length() > 0 && password != null && password.length() > 0)) {
            log.warn("User or password empty");
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_AUTHENTICATION);
        }

        Subject subject;
        try {
            CallbackHandler handler = getCallbackHandler(user, password);  
            LoginContext ctx = new LoginContext(getContextName(), handler);  
            ctx.login();
            subject = ctx.getSubject();
        } catch (LoginException ex) {
            log.info("Authentication failed", ex);
            throw new WSSecurityException(
                WSSecurityException.ErrorCode.FAILED_AUTHENTICATION, ex
            );
        }
        
        UsernameSecurityToken usernameSecurityToken = new UsernameSecurityToken(
                username.getValue(), password, null, null, null, 0L,
                tokenContext.getWsSecurityContext(), usernameTokenType.getId(),
                WSSConstants.WSSKeyIdentifierType.SECURITY_TOKEN_DIRECT_REFERENCE);
        usernameSecurityToken.setElementPath(tokenContext.getElementPath());
        usernameSecurityToken.setXMLSecEvent(tokenContext.getFirstXMLSecEvent());
        usernameSecurityToken.setSubject(subject);
        
        WSUsernameTokenPrincipal principal = 
            new WSUsernameTokenPrincipal(username.getValue(), false);
        final EncodedString encodedNonce =
            XMLSecurityUtils.getQNameType(usernameTokenType.getAny(), WSSConstants.TAG_wsse_Nonce);
        if (encodedNonce != null) {
            byte[] nonceVal = Base64.decodeBase64(encodedNonce.getValue());
            try {
                principal.setNonce(new String(nonceVal, "UTF-8"));
            } catch (UnsupportedEncodingException e) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_AUTHENTICATION, e);
            }
        }
        
        principal.setPassword(password);
        final AttributedDateTime attributedDateTimeCreated =
            XMLSecurityUtils.getQNameType(usernameTokenType.getAny(), WSSConstants.TAG_wsu_Created);
        if (attributedDateTimeCreated != null) {
            String created = attributedDateTimeCreated.getValue();
            principal.setCreatedTime(created);
        }
        
        if (passwordType != null && passwordType.getType() != null) {
            principal.setPasswordType(passwordType.getType().toString());
        }
        usernameSecurityToken.setPrincipal(principal);

        return usernameSecurityToken;
    }
    
    protected CallbackHandler getCallbackHandler(String name, String password) {
        return new NamePasswordCallbackHandler(name, password);
    }
}
