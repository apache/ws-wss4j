/*
 * Copyright  2003-2004 The Apache Software Foundation.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
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
import org.w3c.dom.Element;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import java.io.IOException;
import java.security.Principal;
import java.util.Vector;

public class UsernameTokenProcessor implements Processor {
    private static Log log = LogFactory.getLog(UsernameTokenProcessor.class.getName());

    private String utId;
    private UsernameToken ut;
    
    public void handleToken(Element elem, Crypto crypto, Crypto decCrypto, CallbackHandler cb, WSDocInfo wsDocInfo, Vector returnResults, WSSConfig wsc) throws WSSecurityException {
        if (log.isDebugEnabled()) {
            log.debug("Found UsernameToken list element");
        }
        Principal lastPrincipalFound = handleUsernameToken((Element) elem, cb);
        returnResults.add(0, new WSSecurityEngineResult(WSConstants.UT,
                lastPrincipalFound, null, null, null));
        utId = elem.getAttributeNS(WSConstants.WSU_NS, "Id");

    }

    /**
     * Check the UsernameToken element. Depending on the password type
     * contained in the element the processing differs. If the password type
     * is password digest (a hashed password) then process the password
     * commpletely here. Use the callback class to get a stored password
     * perform hash algorithm and compare the result with the transmitted
     * password.
     * <p/>
     * If the password is of type password text or any other yet unknown
     * password type the delegate the password validation to the callback
     * class. To do so the security engine hands over all necessary data to
     * the callback class via the WSPasswordCallback object. To distinguish
     * from digested usernam token the usage parameter of WSPasswordCallback
     * is set to <code>USERNAME_TOKEN_UNKNOWN</code>
     *
     * @param token the DOM element that contains the UsernameToken
     * @param cb    the refernce to the callback object
     * @return WSUsernameTokenPrincipal that contain data that an application
     *         may use to further validate the password/user combination.
     * @throws WSSecurityException
     */
    public WSUsernameTokenPrincipal handleUsernameToken(Element token, CallbackHandler cb) throws WSSecurityException {
        ut = new UsernameToken(token);
        String user = ut.getName();
        String password = ut.getPassword();
        String nonce = ut.getNonce();
        String createdTime = ut.getCreated();
        String pwType = ut.getPasswordType();
        if (log.isDebugEnabled()) {
            log.debug("UsernameToken user " + user);
            log.debug("UsernameToken password " + password);
        }

        Callback[] callbacks = new Callback[1];
        String origPassword = null;
        
        if (ut.isHashed()) {
            if (cb == null) {
                throw new WSSecurityException(WSSecurityException.FAILURE,
                        "noCallback");
            }

            WSPasswordCallback pwCb = new WSPasswordCallback(user, WSPasswordCallback.USERNAME_TOKEN);
            callbacks[0] = pwCb;
            try {
                cb.handle(callbacks);
            } catch (IOException e) {
                throw new WSSecurityException(WSSecurityException.FAILURE,
                        "noPassword",
                        new Object[]{user}, e);
            } catch (UnsupportedCallbackException e) {
                throw new WSSecurityException(WSSecurityException.FAILURE,
                        "noPassword",
                        new Object[]{user}, e);
            }
            origPassword = pwCb.getPassword();
            if (log.isDebugEnabled()) {
                log.debug("UsernameToken callback password " + origPassword);
            }
            if (origPassword == null) {
                throw new WSSecurityException(WSSecurityException.FAILURE,
                        "noPassword", new Object[]{user});
            }
            if (nonce != null && createdTime != null) {
                String passDigest = UsernameToken.doPasswordDigest(nonce, createdTime, origPassword);
                if (!passDigest.equals(password)) {
                    throw new WSSecurityException(WSSecurityException.FAILED_AUTHENTICATION);
                }
            }
            ut.setRawPassword(origPassword);
        } else if (cb != null) {
            WSPasswordCallback pwCb = new WSPasswordCallback(user, password,
                    pwType, WSPasswordCallback.USERNAME_TOKEN_UNKNOWN);
            callbacks[0] = pwCb;
            try {
                cb.handle(callbacks);
            } catch (IOException e) {
                throw new WSSecurityException(WSSecurityException.FAILURE,
                        "noPassword", new Object[]{user});
            } catch (UnsupportedCallbackException e) {
                throw new WSSecurityException(WSSecurityException.FAILURE,
                        "noPassword", new Object[]{user});
            }
            ut.setRawPassword(password);
        }
        WSUsernameTokenPrincipal principal = new WSUsernameTokenPrincipal(user, ut.isHashed());
        principal.setNonce(nonce);
        principal.setPassword(password);
        principal.setCreatedTime(createdTime);
        principal.setPasswordType(pwType);

        return principal;
    }

    /* (non-Javadoc)
     * @see org.apache.ws.security.processor.Processor#getId()
     */
    public String getId() {
    	return utId;
    }

    /**
     * Get the processed USernameToken.
     * 
     * @return the ut
     */
    public UsernameToken getUt() {
        return ut;
    }    
}
