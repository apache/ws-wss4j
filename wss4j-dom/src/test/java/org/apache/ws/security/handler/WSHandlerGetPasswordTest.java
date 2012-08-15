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

import org.apache.ws.security.WSPasswordCallback;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.common.CustomHandler;
import org.apache.ws.security.common.SOAPUtil;
import org.apache.ws.security.common.UsernamePasswordCallbackHandler;
import org.w3c.dom.Document;

import javax.security.auth.callback.CallbackHandler;

/**
 * WS-Security Test Case for the getPassword method in WSHandler.
 * <p/>
 */
public class WSHandlerGetPasswordTest extends org.junit.Assert {
    private static final org.apache.commons.logging.Log LOG = 
        org.apache.commons.logging.LogFactory.getLog(WSHandlerGetPasswordTest.class);
    private CallbackHandler callbackHandler = new UsernamePasswordCallbackHandler();

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
    
}
