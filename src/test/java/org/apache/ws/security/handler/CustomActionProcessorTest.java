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

import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.common.CustomAction;
import org.apache.ws.security.common.CustomHandler;
import org.apache.ws.security.common.CustomProcessor;
import org.apache.ws.security.common.SOAPUtil;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.ws.security.message.WSSecSignature;
import org.apache.ws.security.message.WSSecHeader;
import org.apache.ws.security.util.WSSecurityUtil;
import org.w3c.dom.Document;

import java.util.List;
import java.util.ArrayList;


/**
 * A test for adding custom actions/processors etc.
 */
public class CustomActionProcessorTest extends org.junit.Assert {
    private static final org.apache.commons.logging.Log LOG = 
        org.apache.commons.logging.LogFactory.getLog(CustomActionProcessorTest.class);
    private Crypto crypto = null;
    
    public CustomActionProcessorTest() throws Exception {
        WSSConfig.init();
        crypto = CryptoFactory.getInstance();
    }

    /**
     * Test to see that a custom processor configured through a 
     * WSSConfig instance is called
     */
    @org.junit.Test
    public void 
    testCustomUserProcessor() throws Exception {
        WSSecSignature builder = new WSSecSignature();
        builder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        builder.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);
        LOG.info("Before Signing IS....");
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        Document signedDoc = builder.build(doc, crypto, secHeader);

        if (LOG.isDebugEnabled()) {
            LOG.debug("Signed message with IssuerSerial key identifier:");
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        LOG.info("After Signing IS....");
        //
        // Check to make sure we can install/replace and use our own processor
        //
        WSSConfig cfg = WSSConfig.getNewInstance();
        String p = "org.apache.ws.security.common.CustomProcessor";
        cfg.setProcessor(
            WSSecurityEngine.SIGNATURE,
            org.apache.ws.security.common.CustomProcessor.class
        );
        final WSSecurityEngine engine = new WSSecurityEngine();
        engine.setWssConfig(cfg);
        final List<WSSecurityEngineResult> results = 
            engine.processSecurityHeader(doc, null, null, crypto);
        boolean found = false;
        for (WSSecurityEngineResult result : results) {
            Object obj = result.get("foo");
            if (obj != null) {
                if (obj.getClass().getName().equals(p)) {
                    found = true;
                }
            }
        }
        assertTrue("Unable to find result from CustomProcessor", found);
    }
    
    /**
     * Test to see that a custom processor (object) configured through a 
     * WSSConfig instance is called
     */
    @org.junit.Test
    public void 
    testCustomUserProcessorObject() throws Exception {
        WSSecSignature builder = new WSSecSignature();
        builder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        builder.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);
        LOG.info("Before Signing IS....");
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        Document signedDoc = builder.build(doc, crypto, secHeader);

        if (LOG.isDebugEnabled()) {
            LOG.debug("Signed message with IssuerSerial key identifier:");
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        LOG.info("After Signing IS....");
        //
        // Check to make sure we can install/replace and use our own processor
        //
        WSSConfig cfg = WSSConfig.getNewInstance();
        cfg.setProcessor(
            WSSecurityEngine.SIGNATURE,
            CustomProcessor.class
        );
        final WSSecurityEngine engine = new WSSecurityEngine();
        engine.setWssConfig(cfg);
        final List<WSSecurityEngineResult> results = 
            engine.processSecurityHeader(doc, null, null, crypto);
        boolean found = false;
        for (WSSecurityEngineResult result : results) {
            Object obj = result.get("foo");
            if (obj != null) {
                if (obj.getClass().getName().equals(CustomProcessor.class.getName())) {
                    found = true;
                }
            }
        }
        assertTrue("Unable to find result from CustomProcessor", found);
    }
    
    /**
     * Test to see that a custom action configured through a
     * WSSConfig instance is called
     */
    @org.junit.Test
    public void
    testCustomAction() throws Exception {
        
        final WSSConfig cfg = WSSConfig.getNewInstance();
        final int action = 0xDEADF000;
        cfg.setAction(action, org.apache.ws.security.common.CustomAction.class);
        final RequestData reqData = new RequestData();
        reqData.setWssConfig(cfg);
        
        final List<Integer> actions = new ArrayList<Integer>();
        actions.add(Integer.valueOf(action));
        final Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        CustomHandler handler = new CustomHandler();
        reqData.setMsgContext("bread");
        assertEquals(reqData.getMsgContext(), "bread");
        handler.send(
            action, 
            doc, 
            reqData, 
            actions,
            true
        );
        assertEquals(reqData.getMsgContext(), "crumb");
    }
    
    /**
     * Test to see that a custom action object configured through a
     * WSSConfig instance is called
     */
    @org.junit.Test
    public void
    testCustomActionObject() throws Exception {
        
        final WSSConfig cfg = WSSConfig.getNewInstance();
        final int action = 0xDEADF000;
        cfg.setAction(action, CustomAction.class);
        final RequestData reqData = new RequestData();
        reqData.setWssConfig(cfg);
        
        final List<Integer> actions = new ArrayList<Integer>();
        actions.add(Integer.valueOf(action));
        final Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        CustomHandler handler = new CustomHandler();
        reqData.setMsgContext("bread");
        assertEquals(reqData.getMsgContext(), "bread");
        handler.send(
            action, 
            doc, 
            reqData, 
            actions,
            true
        );
        assertEquals(reqData.getMsgContext(), "crumb");
    }
    
    /**
     * Test to see that a custom action can be configured via WSSecurityUtil.decodeAction.
     * A standard Timestamp action is also configured.
     */
    @org.junit.Test
    public void
    testDecodeCustomAction() throws Exception {
        
        final WSSConfig cfg = WSSConfig.getNewInstance();
        final int customAction = 0xDEADF000;
        
        String actionString = 
            WSHandlerConstants.TIMESTAMP + " " + Integer.valueOf(customAction).toString();
        List<Integer> actionList = new ArrayList<Integer>();
        //
        // This parsing will fail as it doesn't know what the custom action is
        //
        try {
            WSSecurityUtil.decodeAction(actionString, actionList);
            fail("Failure expected on unknown action");
        } catch (WSSecurityException ex) {
            // expected
        }
        actionList.clear();
        
        //
        // This parsing will fail as WSSConfig doesn't know what the custom action is
        //
        try {
            WSSecurityUtil.decodeAction(actionString, actionList, cfg);
            fail("Failure expected on unknown action");
        } catch (WSSecurityException ex) {
            // expected
        }
        actionList.clear();
        
        //
        // This parsing will fail as the action String is badly formed
        //
        try {
            String badActionString = 
                WSHandlerConstants.TIMESTAMP + " " + "NewCustomAction";
            WSSecurityUtil.decodeAction(badActionString, actionList, cfg);
            fail("Failure expected on unknown action");
        } catch (WSSecurityException ex) {
            // expected
        }
        actionList.clear();
        
        //
        // This parsing should pass as WSSConfig has been configured with the custom action
        //
        cfg.setAction(customAction, org.apache.ws.security.common.CustomAction.class);
        int actions = WSSecurityUtil.decodeAction(actionString, actionList, cfg);
        
        final RequestData reqData = new RequestData();
        reqData.setWssConfig(cfg);
        
        final Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        CustomHandler handler = new CustomHandler();
        reqData.setMsgContext("bread");
        assertEquals(reqData.getMsgContext(), "bread");
        handler.send(
            actions, 
            doc, 
            reqData, 
            actionList,
            true
        );
        assertEquals(reqData.getMsgContext(), "crumb");
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("Message:");
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }
    }

}
