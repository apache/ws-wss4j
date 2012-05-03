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

package org.apache.ws.security.handler;

import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.common.CustomHandler;
import org.apache.ws.security.common.SOAPUtil;
import org.apache.ws.security.common.UsernamePasswordCallbackHandler;
import org.w3c.dom.Document;

import javax.security.auth.callback.CallbackHandler;

/**
 * Test case for WSS-245 - "WSHandlerConstants.PW_CALLBACK_REF isn't correctly searched for"
 *
 * https://issues.apache.org/jira/browse/WSS-245
 */
public class CallbackRefTest extends org.junit.Assert {
    private static final org.apache.commons.logging.Log LOG = 
        org.apache.commons.logging.LogFactory.getLog(CallbackRefTest.class);
    private CallbackHandler callbackHandler = new UsernamePasswordCallbackHandler();
    
    /**
     * A test for WSHandler.getPassword(...), where the password is obtained from a 
     * Callback Handler, which is placed on the Message Context using a reference.
     */
    @org.junit.Test
    public void
    testMessageContextRef() throws Exception {
        
        final WSSConfig cfg = WSSConfig.getNewInstance();
        final RequestData reqData = new RequestData();
        reqData.setWssConfig(cfg);
        reqData.setUsername("alice");
        reqData.setPwType(WSConstants.PASSWORD_TEXT);
        java.util.Map<String, Object> messageContext = new java.util.TreeMap<String, Object>();
        messageContext.put(
            WSHandlerConstants.PW_CALLBACK_REF, 
            callbackHandler
        );
        reqData.setMsgContext(messageContext);
        
        final java.util.List<Integer> actions = new java.util.ArrayList<Integer>();
        actions.add(Integer.valueOf(WSConstants.UT));
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        CustomHandler handler = new CustomHandler();
        handler.send(
            WSConstants.UT, 
            doc, 
            reqData, 
            actions,
            true
        );
        
        String outputString = 
            org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
        if (LOG.isDebugEnabled()) {
            LOG.debug(outputString);
        }
        assertTrue(outputString.indexOf("alice") != -1);
        assertTrue(outputString.indexOf("securityPassword") != -1);
    }
    
    /**
     * A test for WSHandler.getPassword(...) where the password is obtained from a 
     * Callback Handler, which is obtained from the handler options using a ref.
     */
    @org.junit.Test
    public void
    testHandlerOptionRef() throws Exception {
        
        final WSSConfig cfg = WSSConfig.getNewInstance();
        final RequestData reqData = new RequestData();
        reqData.setWssConfig(cfg);
        reqData.setUsername("alice");
        reqData.setPwType(WSConstants.PASSWORD_TEXT);
        reqData.setMsgContext(new java.util.TreeMap<String, String>());
        
        final java.util.List<Integer> actions = new java.util.ArrayList<Integer>();
        actions.add(Integer.valueOf(WSConstants.UT));
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        CustomHandler handler = new CustomHandler();
        handler.setOption(WSHandlerConstants.PW_CALLBACK_REF, callbackHandler);
        handler.send(
            WSConstants.UT, 
            doc, 
            reqData, 
            actions,
            true
        );
        
        String outputString = 
            org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
        if (LOG.isDebugEnabled()) {
            LOG.debug(outputString);
        }
        assertTrue(outputString.indexOf("alice") != -1);
        assertTrue(outputString.indexOf("securityPassword") != -1);
    }
    
}
