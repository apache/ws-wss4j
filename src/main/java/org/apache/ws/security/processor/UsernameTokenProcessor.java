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

package org.apache.ws.security.processor;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSDocInfo;
import org.apache.ws.security.WSPasswordCallback;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.WSUsernameTokenPrincipal;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.message.token.UsernameToken;
import org.apache.ws.security.util.Base64;
import org.w3c.dom.Element;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import java.io.IOException;
import java.util.List;

public class UsernameTokenProcessor implements Processor {
    private static Log log = LogFactory.getLog(UsernameTokenProcessor.class.getName());

    public List<WSSecurityEngineResult> handleToken(
        Element elem, Crypto crypto, Crypto decCrypto, CallbackHandler cb, 
        WSDocInfo wsDocInfo, WSSConfig wsc
    ) throws WSSecurityException {
        if (log.isDebugEnabled()) {
            log.debug("Found UsernameToken list element");
        }
        
        UsernameToken token = handleUsernameToken(elem, cb, wsc);
        
        WSUsernameTokenPrincipal principal = 
            new WSUsernameTokenPrincipal(token.getName(), token.isHashed());
        principal.setNonce(token.getNonce());
        principal.setPassword(token.getPassword());
        principal.setCreatedTime(token.getCreated());
        principal.setPasswordType(token.getPasswordType());
        
        WSSecurityEngineResult result = 
            new WSSecurityEngineResult(WSConstants.UT, token, principal);
        result.put(WSSecurityEngineResult.TAG_ID, token.getID());
        wsDocInfo.addTokenElement(elem);
        wsDocInfo.addResult(result);
        return java.util.Collections.singletonList(result);
    }

    /**
     * Check the UsernameToken element. If the password type is plaintext or digested, 
     * then retrieve a password from the callback handler and authenticate the UsernameToken
     * here.
     * <p/>
     * If the password is any other yet unknown password type then delegate the password
     * validation to the callback class. Note that for unknown password types an exception
     * is thrown if WSSConfig.getHandleCustomPasswordTypes() is set to false (as it is 
     * by default). The security engine hands over all necessary data to the callback class
     * via the WSPasswordCallback object. The usage parameter of WSPasswordCallback is set to
     * <code>USERNAME_TOKEN_UNKNOWN</code>.
     *
     * @param token the DOM element that contains the UsernameToken
     * @param cb    the reference to the callback object
     * @param wssConfig The WSSConfig object from which to obtain configuration
     * @return UsernameToken the UsernameToken object that was parsed
     * @throws WSSecurityException
     */
    public UsernameToken 
    handleUsernameToken(
        Element token, 
        CallbackHandler cb,
        WSSConfig wssConfig
    ) throws WSSecurityException {
        if (cb == null) {
            throw new WSSecurityException(WSSecurityException.FAILURE, "noCallback");
        }
        boolean handleCustomPasswordTypes = false;
        boolean allowNamespaceQualifiedPasswordTypes = false;
        boolean passwordsAreEncoded = false;
        
        if (wssConfig != null) {
            handleCustomPasswordTypes = wssConfig.getHandleCustomPasswordTypes();
            allowNamespaceQualifiedPasswordTypes = 
                wssConfig.getAllowNamespaceQualifiedPasswordTypes();
            passwordsAreEncoded = wssConfig.getPasswordsAreEncoded();
        }
        
        //
        // Parse the UsernameToken element
        //
        UsernameToken ut = new UsernameToken(token, allowNamespaceQualifiedPasswordTypes);
        ut.setPasswordsAreEncoded(passwordsAreEncoded);
        String user = ut.getName();
        String password = ut.getPassword();
        String nonce = ut.getNonce();
        String createdTime = ut.getCreated();
        String pwType = ut.getPasswordType();
        if (log.isDebugEnabled()) {
            log.debug("UsernameToken user " + user);
            log.debug("UsernameToken password type " + pwType);
        }
        
        if (wssConfig != null) {
            String requiredPasswordType = wssConfig.getRequiredPasswordType();
            if (requiredPasswordType != null && !requiredPasswordType.equals(pwType)) {
                if (log.isDebugEnabled()) {
                    log.debug("Authentication failed as the received password type does not " 
                        + "match the required password type of: " + requiredPasswordType);
                }
                throw new WSSecurityException(WSSecurityException.FAILED_AUTHENTICATION);
            }
        }
        //
        // If the UsernameToken is hashed or plaintext, then retrieve the password from the
        // callback handler and compare directly. If the UsernameToken is of some unknown type,
        // then delegate authentication to the callback handler
        //
        if (ut.isHashed() || WSConstants.PASSWORD_TEXT.equals(pwType) 
            || (password != null && (pwType == null || "".equals(pwType.trim())))) {
            WSPasswordCallback pwCb = 
                new WSPasswordCallback(user, null, pwType, WSPasswordCallback.USERNAME_TOKEN);
            try {
                cb.handle(new Callback[]{pwCb});
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
            if (ut.isHashed()) {
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
            ut.setRawPassword(origPassword);
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
                cb.handle(new Callback[]{pwCb});
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
            ut.setRawPassword(origPassword);
        }

        return ut;
    }

}
