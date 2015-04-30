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

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import org.apache.wss4j.common.SecurityActionToken;
import org.apache.wss4j.common.ext.WSPasswordCallback;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.handler.WSHandler;

public class CustomTokenAction implements Action {
    
    public void execute(WSHandler handler, SecurityActionToken actionToken,
                        Document doc, RequestData reqData)
        throws WSSecurityException {
        CallbackHandler callbackHandler = reqData.getCallbackHandler();
        if (callbackHandler == null) {
            callbackHandler = handler.getPasswordCallbackHandler(reqData);
        }
        
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
                    "empty", new Object[] {"WSHandler: password callback failed"});
        }
        
        Element customToken = wsPasswordCallback.getCustomToken();
        if (customToken == null) {
            throw new WSSecurityException(
                WSSecurityException.ErrorCode.FAILURE, "resourceNotFound", new Object[] {"CustomToken"}
            );
        }
        
        Element securityHeader = reqData.getSecHeader().getSecurityHeader();
        securityHeader.appendChild(securityHeader.getOwnerDocument().adoptNode(customToken));
    }
}
