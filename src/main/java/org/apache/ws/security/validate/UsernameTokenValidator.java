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

import java.io.IOException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSPasswordCallback;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.message.token.UsernameToken;
import org.apache.ws.security.util.Base64;

/**
 * This interface describes a pluggable way of validating credentials that have been extracted
 * by the processors.
 */
public class UsernameTokenValidator implements Validator {
    
    private static Log log = LogFactory.getLog(UsernameTokenValidator.class.getName());
    
    private WSSConfig wssConfig;
    private CallbackHandler callbackHandler;
    
    public void validate(Credential credential) throws WSSecurityException {
        if (credential == null) {
            throw new WSSecurityException("Credential cannot be null");
        }
        if (wssConfig == null) {
            throw new WSSecurityException("WSSConfig cannot be null");
        }
        if (callbackHandler == null) {
            throw new WSSecurityException(WSSecurityException.FAILURE, "noCallback");
        }
        
        boolean handleCustomPasswordTypes = wssConfig.getHandleCustomPasswordTypes();
        boolean passwordsAreEncoded = wssConfig.getPasswordsAreEncoded();
        
        UsernameToken usernameToken = credential.getUsernametoken();
        if (usernameToken == null) {
            throw new WSSecurityException("Username Token cannot be null");
        }
        usernameToken.setPasswordsAreEncoded(passwordsAreEncoded);
        
        String user = usernameToken.getName();
        String password = usernameToken.getPassword();
        String nonce = usernameToken.getNonce();
        String createdTime = usernameToken.getCreated();
        String pwType = usernameToken.getPasswordType();
        if (log.isDebugEnabled()) {
            log.debug("UsernameToken user " + user);
            log.debug("UsernameToken password type " + pwType);
        }
        
        String requiredPasswordType = wssConfig.getRequiredPasswordType();
        if (requiredPasswordType != null && !requiredPasswordType.equals(pwType)) {
            if (log.isDebugEnabled()) {
                log.debug("Authentication failed as the received password type does not " 
                    + "match the required password type of: " + requiredPasswordType);
            }
            throw new WSSecurityException(WSSecurityException.FAILED_AUTHENTICATION);
        }
        
        
        //
        // If the UsernameToken is hashed or plaintext, then retrieve the password from the
        // callback handler and compare directly. If the UsernameToken is of some unknown type,
        // then delegate authentication to the callback handler
        //
        if (usernameToken.isHashed() || WSConstants.PASSWORD_TEXT.equals(pwType) 
            || (password != null && (pwType == null || "".equals(pwType.trim())))) {
            WSPasswordCallback pwCb = 
                new WSPasswordCallback(user, null, pwType, WSPasswordCallback.USERNAME_TOKEN);
            try {
                callbackHandler.handle(new Callback[]{pwCb});
            } catch (IOException e) {
                if (log.isDebugEnabled()) {
                    log.debug(e);
                }
                throw new WSSecurityException(
                    WSSecurityException.FAILED_AUTHENTICATION, null, null, e
                );
            } catch (UnsupportedCallbackException e) {
                if (log.isDebugEnabled()) {
                    log.debug(e);
                }
                throw new WSSecurityException(
                    WSSecurityException.FAILED_AUTHENTICATION, null, null, e
                );
            }
            String origPassword = pwCb.getPassword();
            if (origPassword == null) {
                if (log.isDebugEnabled()) {
                    log.debug("Callback supplied no password for: " + user);
                }
                throw new WSSecurityException(WSSecurityException.FAILED_AUTHENTICATION);
            }
            if (usernameToken.isHashed()) {
                String passDigest;
                if (passwordsAreEncoded) {
                    passDigest = UsernameToken.doPasswordDigest(nonce, createdTime, Base64.decode(origPassword));
                } else {
                    passDigest = UsernameToken.doPasswordDigest(nonce, createdTime, origPassword);
                }
                if (!passDigest.equals(password)) {
                    throw new WSSecurityException(WSSecurityException.FAILED_AUTHENTICATION);
                }
            } else {
                if (!origPassword.equals(password)) {
                    throw new WSSecurityException(WSSecurityException.FAILED_AUTHENTICATION);
                }
            }
            usernameToken.setRawPassword(origPassword);
        } else {
            if (pwType != null && !handleCustomPasswordTypes) {
                if (log.isDebugEnabled()) {
                    log.debug("Authentication failed as handleCustomUsernameTokenTypes is false");
                }
                throw new WSSecurityException(WSSecurityException.FAILED_AUTHENTICATION);
            }
            WSPasswordCallback pwCb = new WSPasswordCallback(user, password,
                    pwType, WSPasswordCallback.USERNAME_TOKEN_UNKNOWN);
            try {
                callbackHandler.handle(new Callback[]{pwCb});
            } catch (IOException e) {
                if (log.isDebugEnabled()) {
                    log.debug(e);
                }
                throw new WSSecurityException(
                    WSSecurityException.FAILED_AUTHENTICATION, null, null, e
                );
            } catch (UnsupportedCallbackException e) {
                if (log.isDebugEnabled()) {
                    log.debug(e);
                }
                throw new WSSecurityException(
                    WSSecurityException.FAILED_AUTHENTICATION, null, null, e
                );
            }
            String origPassword = pwCb.getPassword();
            usernameToken.setRawPassword(origPassword);
        }
        
    }
    
    public void setWSSConfig(WSSConfig wssConfig) {
        this.wssConfig = wssConfig;
    }
    
    public void setCrypto(Crypto crypto) {
        //
    }
    
    public void setCallbackHandler(CallbackHandler callbackHandler) {
        this.callbackHandler = callbackHandler;
    }
   
}
