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

package org.apache.wss4j.dom.handler;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.wss4j.common.ext.WSPasswordCallback;
import org.apache.wss4j.common.util.XMLUtils;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.common.CustomHandler;
import org.apache.wss4j.dom.common.SOAPUtil;
import org.apache.wss4j.dom.common.SecurityTestUtil;
import org.apache.wss4j.dom.engine.WSSConfig;
import org.apache.wss4j.dom.engine.WSSecurityEngine;
import org.apache.wss4j.dom.engine.WSSecurityEngineResult;
import org.apache.wss4j.dom.message.WSSecTimestamp;
import org.apache.wss4j.dom.message.token.Timestamp;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import static org.junit.Assert.assertNotNull;


/**
 * A test to add a Custom Token to an outbound message
 */
public class CustomTokenTest {
    private static final org.slf4j.Logger LOG =
        org.slf4j.LoggerFactory.getLogger(CustomTokenTest.class);

    @org.junit.AfterClass
    public static void cleanup() throws Exception {
        SecurityTestUtil.cleanup();
    }

    // Add a Timestamp via a "Custom Token"
    @Test
    public void testCustomTokenTimestamp() throws Exception {
        // Create a Timestamp manually
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        Document timestampDoc = dbf.newDocumentBuilder().newDocument();

        WSSecTimestamp timestamp = new WSSecTimestamp(timestampDoc);
        timestamp.setTimeToLive(300);
        timestamp.prepare();
        Element timestampElement = timestamp.getElement();

        final WSSConfig cfg = WSSConfig.getNewInstance();
        final RequestData reqData = new RequestData();
        reqData.setWssConfig(cfg);
        java.util.Map<String, Object> messageContext = new java.util.TreeMap<>();
        messageContext.put(
            WSHandlerConstants.PW_CALLBACK_REF, new CustomCallbackHandler(timestampElement)
        );
        reqData.setMsgContext(messageContext);

        final Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        CustomHandler handler = new CustomHandler();
        List<HandlerAction> actions = new ArrayList<>();
        actions.add(new HandlerAction(WSConstants.CUSTOM_TOKEN, null));
        handler.send(
            doc,
            reqData,
            actions,
            true
        );

        if (LOG.isDebugEnabled()) {
            String outputString =
                XMLUtils.prettyDocumentToString(doc);
            LOG.debug(outputString);
        }

        WSSecurityEngine secEngine = new WSSecurityEngine();
        WSHandlerResult wsResults =
            secEngine.processSecurityHeader(doc, null, null, null);
        WSSecurityEngineResult actionResult =
            wsResults.getActionResults().get(WSConstants.TS).get(0);
        assertNotNull(actionResult);

        Timestamp receivedTimestamp =
            (Timestamp)actionResult.get(WSSecurityEngineResult.TAG_TIMESTAMP);
        assertNotNull(receivedTimestamp);
    }

    private static class CustomCallbackHandler implements CallbackHandler {

        private final Element customElement;

        public CustomCallbackHandler(Element customElement) {
            this.customElement = customElement;
        }

        @Override
        public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
            for (Callback callback : callbacks) {
                if (callback instanceof WSPasswordCallback) {
                    WSPasswordCallback passwordCallback = (WSPasswordCallback)callback;
                    if (passwordCallback.getUsage() == WSPasswordCallback.CUSTOM_TOKEN) {
                        passwordCallback.setCustomToken(customElement);
                        return;
                    }
                }
            }

        }

    }

}