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

import javax.security.auth.callback.CallbackHandler;

import org.apache.wss4j.common.SecurityActionToken;
import org.apache.wss4j.common.ext.WSPasswordCallback;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.handler.WSHandler;
import org.apache.wss4j.dom.message.WSSecUsernameToken;

public class UsernameTokenAction implements Action {

    public void execute(WSHandler handler, SecurityActionToken actionToken, RequestData reqData)
        throws WSSecurityException {
        String username = reqData.getUsername();
        String password = null;
        if (reqData.getPwType() != null) {
            CallbackHandler callbackHandler =
                handler.getPasswordCallbackHandler(reqData);
            WSPasswordCallback passwordCallback =
                handler.getPasswordCB(reqData.getUsername(), WSConstants.UT, callbackHandler, reqData);
            username = passwordCallback.getIdentifier();
            password = passwordCallback.getPassword();
        }

        if (username == null) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "noUser");
        }

        WSSecUsernameToken builder = new WSSecUsernameToken(reqData.getSecHeader());
        builder.setIdAllocator(reqData.getWssConfig().getIdAllocator());
        builder.setPrecisionInMilliSeconds(reqData.isPrecisionInMilliSeconds());
        builder.setWsTimeSource(reqData.getWssConfig().getCurrentTime());
        builder.setPasswordType(reqData.getPwType());
        builder.setPasswordsAreEncoded(reqData.isEncodePasswords());
        builder.setUserInfo(username, password);
        builder.setWsDocInfo(reqData.getWsDocInfo());

        if (reqData.isAddUsernameTokenNonce()) {
            builder.addNonce();
        }

        if (reqData.isAddUsernameTokenCreated()) {
            builder.addCreated();
        }

        builder.build();
    }
}
