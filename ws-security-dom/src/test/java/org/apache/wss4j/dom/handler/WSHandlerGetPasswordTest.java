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

import java.util.Collections;

import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.WSSConfig;
import org.apache.wss4j.dom.common.CustomHandler;
import org.apache.wss4j.dom.common.SOAPUtil;
import org.apache.wss4j.dom.common.SecurityTestUtil;
import org.apache.wss4j.dom.common.UsernamePasswordCallbackHandler;
import org.apache.wss4j.common.ext.WSPasswordCallback;
import org.apache.wss4j.common.util.XMLUtils;
import org.w3c.dom.Document;

import javax.security.auth.callback.CallbackHandler;

/**
 * WS-Security Test Case for the getPassword method in WSHandler.
 * <p/>
 */
public class WSHandlerGetPasswordTest extends org.junit.Assert {
    private static final org.slf4j.Logger LOG = 
        org.slf4j.LoggerFactory.getLogger(WSHandlerGetPasswordTest.class);
    private CallbackHandler callbackHandler = new UsernamePasswordCallbackHandler();

    @org.junit.AfterClass
    public static void cleanup() throws Exception {
        SecurityTestUtil.cleanup();
    }
    
    /**
     * A unit test for WSHandler.getPassword(...), where the password is obtained 
     * from the Message Context.
     */
    @org.junit.Test
    public void
    testGetPasswordRequestContextUnit() throws Exception {
        
        final WSSConfig cfg = WSSConfig.getNewInstance();
        final RequestData reqData = new RequestData();
        reqData.setWssConfig(cfg);
        java.util.Map<String, Object> messageContext = new java.util.TreeMap<String, Object>();
        messageContext.put("password", "securityPassword");
        reqData.setMsgContext(messageContext);
        
        WSHandler handler = new CustomHandler();
        CallbackHandler callbackHandler = 
            handler.getCallbackHandler("SomeCallbackTag", "SomeCallbackRef", reqData);
        WSPasswordCallback callback = 
            handler.getPasswordCB("alice", WSConstants.UT, callbackHandler, reqData);
        assertTrue("alice".equals(callback.getIdentifier()));
        assertTrue("securityPassword".equals(callback.getPassword()));
        assertTrue(WSPasswordCallback.USERNAME_TOKEN == callback.getUsage());
    }
    
    /**
     * A WSHandler test for WSHandler.getPassword(...), where the password is obtained 
     * from the Message Context.
     */
    @org.junit.Test
    public void
    testGetPasswordRequestContext() throws Exception {
        
        final WSSConfig cfg = WSSConfig.getNewInstance();
        final RequestData reqData = new RequestData();
        reqData.setWssConfig(cfg);
        reqData.setUsername("alice");
        reqData.setPwType(WSConstants.PASSWORD_TEXT);
        java.util.Map<String, Object> messageContext = new java.util.TreeMap<String, Object>();
        messageContext.put("password", "securityPassword");
        reqData.setMsgContext(messageContext);
        
        final java.util.List<Integer> actions = new java.util.ArrayList<Integer>();
        actions.add(WSConstants.UT);
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        CustomHandler handler = new CustomHandler();
        HandlerAction action = new HandlerAction(WSConstants.UT);
        handler.send(
            doc, 
            reqData, 
            Collections.singletonList(action),
            true
        );
        
        String outputString = 
            XMLUtils.PrettyDocumentToString(doc);
        if (LOG.isDebugEnabled()) {
            LOG.debug(outputString);
        }
        assertTrue(outputString.contains("alice"));
        assertTrue(outputString.contains("securityPassword"));
    }
    
    /**
     * A test for WSHandler.getPassword(...), where the password is obtained from a 
     * Callback Handler, which is placed on the Message Context using a reference.
     */
    @org.junit.Test
    public void
    testGetPasswordCallbackHandlerRef() throws Exception {
        
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
        actions.add(WSConstants.UT);
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        CustomHandler handler = new CustomHandler();
        HandlerAction action = new HandlerAction(WSConstants.UT);
        handler.send(
            doc, 
            reqData, 
            Collections.singletonList(action),
            true
        );
        
        String outputString = 
            XMLUtils.PrettyDocumentToString(doc);
        if (LOG.isDebugEnabled()) {
            LOG.debug(outputString);
        }
        assertTrue(outputString.contains("alice"));
        assertTrue(outputString.contains("securityPassword"));
    }
    
}
