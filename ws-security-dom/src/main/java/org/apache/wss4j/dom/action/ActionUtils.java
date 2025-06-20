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

package org.apache.wss4j.dom.action;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;

import org.apache.wss4j.common.ext.WSPasswordCallback;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.dom.WSConstants;
import org.apache.wss4j.common.dom.RequestData;

public final class ActionUtils {
    
    private ActionUtils() {
        // Utility class, no instantiation
    }

    /**
     * Construct a WSPasswordCallback instance
     * @param username The username
     * @param doAction The action to perform
     * @return a WSPasswordCallback instance
     * @throws WSSecurityException
     */
    public static WSPasswordCallback constructPasswordCallback(
        String username,
        int doAction
    ) throws WSSecurityException {

        int reason;

        switch (doAction) {
        case WSConstants.UT:
        case WSConstants.UT_SIGN:
            reason = WSPasswordCallback.USERNAME_TOKEN;
            break;
        case WSConstants.SIGN:
            reason = WSPasswordCallback.SIGNATURE;
            break;
        case WSConstants.DKT_SIGN:
            reason = WSPasswordCallback.SECRET_KEY;
            break;
        case WSConstants.ENCR:
            reason = WSPasswordCallback.SECRET_KEY;
            break;
        case WSConstants.DKT_ENCR:
            reason = WSPasswordCallback.SECRET_KEY;
            break;
        default:
            reason = WSPasswordCallback.UNKNOWN;
            break;
        }
        return new WSPasswordCallback(username, reason);
    }

    /**
     * Configure a password callback (WSPasswordCallback object) from a CallbackHandler instance
     * @param callbackHandler The CallbackHandler to use
     * @param pwCb The WSPasswordCallback to supply to the CallbackHandler
     * @param requestData The RequestData which supplies the message context
     * @throws WSSecurityException
     */
    public static void performPasswordCallback(
         CallbackHandler callbackHandler,
         WSPasswordCallback pwCb,
         RequestData requestData
    ) throws WSSecurityException {

        if (callbackHandler != null) {
            Callback[] callbacks = new Callback[1];
            callbacks[0] = pwCb;
            //
            // Call back the application to get the password
            //
            try {
                callbackHandler.handle(callbacks);
            } catch (Exception e) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, e,
                        "empty", new Object[] {"WSHandler: password callback failed"});
            }
        }
    }

}
