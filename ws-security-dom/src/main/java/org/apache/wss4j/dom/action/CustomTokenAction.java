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

import org.apache.wss4j.api.dom.SecurityActionToken;
import org.apache.wss4j.common.ext.WSPasswordCallback;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.api.dom.WSConstants;
import org.apache.wss4j.api.dom.RequestData;
import org.apache.wss4j.api.dom.action.Action;
import org.w3c.dom.Element;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;

public class CustomTokenAction implements Action {

    public void execute(SecurityActionToken actionToken, RequestData reqData)
            throws WSSecurityException {
        CallbackHandler callbackHandler = reqData.getCallbackHandler();
        if (callbackHandler == null) {
            throw new WSSecurityException(
                    WSSecurityException.ErrorCode.FAILURE, "noCallback"
            );
        }

        WSPasswordCallback wsPasswordCallback =
                new WSPasswordCallback(reqData.getUsername(), WSPasswordCallback.CUSTOM_TOKEN);

        try {
            callbackHandler.handle(new Callback[]{wsPasswordCallback});
        } catch (Exception e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, e,
                    "empty", new Object[]{"WSHandler: password callback failed"});
        }

        Element customToken = wsPasswordCallback.getCustomToken();
        if (customToken == null) {
            throw new WSSecurityException(
                    WSSecurityException.ErrorCode.FAILURE, "resourceNotFound", new Object[]{"CustomToken"}
            );
        }

        try {
            Element securityHeader = reqData.getSecHeader().getSecurityHeaderElement();
            //Prepare custom token for appending step
            customToken = (Element) securityHeader.getOwnerDocument().importNode(customToken, true);
            //Append custom token to security header
            securityHeader.appendChild(customToken);
        } catch (Exception e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, e,
                    "empty", new Object[] {"Error appending custom token"});
        }
    }

    @Override
    public Integer[] getSupportedActions() {
        return new Integer[]{WSConstants.CUSTOM_TOKEN};
    }
}
