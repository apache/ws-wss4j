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

package org.apache.wss4j.dom.saml.dom;

import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.api.dom.engine.WSSecurityEngineResult;
import org.apache.wss4j.dom.handler.HandlerAction;
import org.apache.wss4j.dom.handler.WSHandler;
import org.apache.wss4j.api.dom.RequestData;
import org.apache.wss4j.dom.handler.WSHandlerResult;
import org.w3c.dom.Document;

import java.util.List;
import java.util.Map;


/**
 * A trivial extension of the WSHandler type for use in unit-testing.
 */
public class CustomHandler extends WSHandler {

    public void send(
        Document doc,
        RequestData reqData,
        List<HandlerAction> actions,
        boolean request
    ) throws WSSecurityException {
        doSenderAction(
            doc,
            reqData,
            actions,
            request
        );
    }

    public void receive(
        List<Integer> actions,
        RequestData reqData
    ) throws WSSecurityException {
        doReceiverAction(
            actions,
            reqData
        );
    }

    public void signatureConfirmation(
        RequestData requestData,
        WSHandlerResult handlerResults
    ) throws WSSecurityException {
        checkSignatureConfirmation(requestData, handlerResults);
    }

    public boolean checkResults(
        List<WSSecurityEngineResult> results,
        List<Integer> actions
    ) throws WSSecurityException {
        return checkReceiverResults(results, actions);
    }

    public boolean checkResultsAnyOrder(
        List<WSSecurityEngineResult> results,
        List<Integer> actions
    ) throws WSSecurityException {
        return checkReceiverResultsAnyOrder(results, actions);
    }

    @SuppressWarnings("unchecked")
    public void setProperty(
        Object ctx,
        String key,
        Object value
    ) {
        ((Map<String, Object>)ctx).put(key, value);
    }

    public Object getProperty(Object ctx, String key) {
        if (ctx instanceof Map<?,?>) {
            return ((Map<?,?>)ctx).get(key);
        }
        return null;
    }

    public String getPassword(Object msgContext) {
        if (msgContext instanceof Map<?,?>) {
            return (String)((Map<?,?>)msgContext).get("password");
        }
        return null;
    }


}
