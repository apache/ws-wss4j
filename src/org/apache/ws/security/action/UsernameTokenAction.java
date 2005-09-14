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

package org.apache.ws.security.action;

import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.handler.RequestData;
import org.apache.ws.security.handler.WSHandler;
import org.apache.ws.security.handler.WSHandlerConstants;
import org.apache.ws.security.message.WSSAddUsernameToken;
import org.w3c.dom.Document;

public class UsernameTokenAction implements Action {
    public void execute(WSHandler handler, int actionToDo, boolean mu, Document doc, RequestData reqData)
            throws WSSecurityException {
        String password;
        password =
                handler.getPassword(reqData.getUsername(),
                        actionToDo,
                        WSHandlerConstants.PW_CALLBACK_CLASS,
                        WSHandlerConstants.PW_CALLBACK_REF, reqData)
                        .getPassword();

        WSSAddUsernameToken builder = new WSSAddUsernameToken(reqData.getActor(), mu);
        builder.setWsConfig(reqData.getWssConfig());
        builder.setPasswordType(reqData.getPwType());

        //Set the wsu:Id of the UNT
        builder.setId("UsernameToken-" + System.currentTimeMillis());

        // add the UsernameToken to the SOAP Enevelope
        builder.build(doc, reqData.getUsername(), password);

        if (reqData.getUtElements() != null && reqData.getUtElements().length > 0) {
            for (int j = 0; j < reqData.getUtElements().length; j++) {
                reqData.getUtElements()[j].trim();
                if (reqData.getUtElements()[j].equals("Nonce")) {
                    builder.addNonce(doc);
                }
                if (reqData.getUtElements()[j].equals("Created")) {
                    builder.addCreated(doc);
                }
                reqData.getUtElements()[j] = null;
            }
        }
    }
}
