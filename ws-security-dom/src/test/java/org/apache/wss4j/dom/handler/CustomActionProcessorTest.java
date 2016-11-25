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

import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.common.CustomAction;
import org.apache.wss4j.dom.common.CustomHandler;
import org.apache.wss4j.dom.common.CustomProcessor;
import org.apache.wss4j.dom.common.SOAPUtil;
import org.apache.wss4j.dom.common.SecurityTestUtil;
import org.apache.wss4j.dom.engine.WSSConfig;
import org.apache.wss4j.dom.engine.WSSecurityEngine;
import org.apache.wss4j.dom.engine.WSSecurityEngineResult;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.util.XMLUtils;
import org.apache.wss4j.dom.message.WSSecSignature;
import org.apache.wss4j.dom.message.WSSecHeader;
import org.apache.wss4j.dom.util.WSSecurityUtil;
import org.junit.Test;
import org.w3c.dom.Document;

import java.util.Collections;
import java.util.List;


/**
 * A test for adding custom actions/processors etc.
 */
public class CustomActionProcessorTest extends org.junit.Assert {
    private static final org.slf4j.Logger LOG =
        org.slf4j.LoggerFactory.getLogger(CustomActionProcessorTest.class);
    private Crypto crypto = null;

    @org.junit.AfterClass
    public static void cleanup() throws Exception {
        SecurityTestUtil.cleanup();
    }

    public CustomActionProcessorTest() throws Exception {
        WSSConfig.init();
        crypto = CryptoFactory.getInstance();
    }

    /**
     * Test to see that a custom processor configured through a
     * WSSConfig instance is called
     */
    @Test
    public void
    testCustomUserProcessor() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();
        
        WSSecSignature builder = new WSSecSignature(secHeader);
        builder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        builder.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);
        LOG.info("Before Signing IS....");
        Document signedDoc = builder.build(doc, crypto);

        if (LOG.isDebugEnabled()) {
            LOG.debug("Signed message with IssuerSerial key identifier:");
            String outputString =
                XMLUtils.prettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        LOG.info("After Signing IS....");
        //
        // Check to make sure we can install/replace and use our own processor
        //
        WSSConfig cfg = WSSConfig.getNewInstance();
        String p = "org.apache.wss4j.dom.common.CustomProcessor";
        cfg.setProcessor(
            WSConstants.SIGNATURE, CustomProcessor.class
        );
        final WSSecurityEngine engine = new WSSecurityEngine();
        engine.setWssConfig(cfg);
        final WSHandlerResult results =
            engine.processSecurityHeader(doc, null, null, crypto);
        boolean found = false;
        for (WSSecurityEngineResult result : results.getResults()) {
            Object obj = result.get("foo");
            if (obj != null && obj.getClass().getName().equals(p)) {
                found = true;
            }
        }
        assertTrue("Unable to find result from CustomProcessor", found);
    }

    /**
     * Test to see that a custom processor (object) configured through a
     * WSSConfig instance is called
     */
    @Test
    public void
    testCustomUserProcessorObject() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();
        
        WSSecSignature builder = new WSSecSignature(secHeader);
        builder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        builder.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);
        LOG.info("Before Signing IS....");
        Document signedDoc = builder.build(doc, crypto);

        if (LOG.isDebugEnabled()) {
            LOG.debug("Signed message with IssuerSerial key identifier:");
            String outputString =
                XMLUtils.prettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        LOG.info("After Signing IS....");
        //
        // Check to make sure we can install/replace and use our own processor
        //
        WSSConfig cfg = WSSConfig.getNewInstance();
        cfg.setProcessor(WSConstants.SIGNATURE, CustomProcessor.class);

        final WSSecurityEngine engine = new WSSecurityEngine();
        engine.setWssConfig(cfg);
        final WSHandlerResult results =
            engine.processSecurityHeader(doc, null, null, crypto);
        boolean found = false;
        for (WSSecurityEngineResult result : results.getResults()) {
            Object obj = result.get("foo");
            if (obj != null && obj.getClass().getName().equals(CustomProcessor.class.getName())) {
                found = true;
            }
        }
        assertTrue("Unable to find result from CustomProcessor", found);
    }

    /**
     * Test to see that a custom action configured through a
     * WSSConfig instance is called
     */
    @Test
    public void
    testCustomAction() throws Exception {

        final WSSConfig cfg = WSSConfig.getNewInstance();
        final int action = 0xDEADF000;
        cfg.setAction(action, CustomAction.class);
        final RequestData reqData = new RequestData();
        reqData.setWssConfig(cfg);

        final Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        CustomHandler handler = new CustomHandler();
        reqData.setMsgContext("bread");
        assertEquals(reqData.getMsgContext(), "bread");
        handler.send(
            doc,
            reqData,
            Collections.singletonList(new HandlerAction(action)),
            true
        );
        assertEquals(reqData.getMsgContext(), "crumb");
    }

    /**
     * Test to see that a custom action object configured through a
     * WSSConfig instance is called
     */
    @Test
    public void
    testCustomActionObject() throws Exception {

        final WSSConfig cfg = WSSConfig.getNewInstance();
        final int action = 0xDEADF000;
        cfg.setAction(action, CustomAction.class);
        final RequestData reqData = new RequestData();
        reqData.setWssConfig(cfg);

        final Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        CustomHandler handler = new CustomHandler();
        reqData.setMsgContext("bread");
        assertEquals(reqData.getMsgContext(), "bread");
        handler.send(
            doc,
            reqData,
            Collections.singletonList(new HandlerAction(action)),
            true
        );
        assertEquals(reqData.getMsgContext(), "crumb");
    }

    /**
     * Test to see that a custom action can be configured via WSSecurityUtil.decodeAction.
     * A standard Timestamp action is also configured.
     */
    @Test
    public void
    testDecodeCustomAction() throws Exception {

        final WSSConfig cfg = WSSConfig.getNewInstance();
        final int customAction = 0xDEADF000;

        String actionString =
            WSHandlerConstants.TIMESTAMP + " " + Integer.valueOf(customAction).toString();
        //
        // This parsing will fail as WSSConfig doesn't know what the custom action is
        //
        try {
            WSSecurityUtil.decodeHandlerAction(actionString, cfg);
            fail("Failure expected on unknown action");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.FAILURE);
        }

        //
        // This parsing will fail as the action String is badly formed
        //
        try {
            String badActionString =
                WSHandlerConstants.TIMESTAMP + " " + "NewCustomAction";
            WSSecurityUtil.decodeHandlerAction(badActionString, cfg);
            fail("Failure expected on unknown action");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.FAILURE);
        }

        //
        // This parsing should pass as WSSConfig has been configured with the custom action
        //
        cfg.setAction(customAction, CustomAction.class);
        List<HandlerAction> actionList = WSSecurityUtil.decodeHandlerAction(actionString, cfg);

        final RequestData reqData = new RequestData();
        reqData.setWssConfig(cfg);

        final Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        CustomHandler handler = new CustomHandler();
        reqData.setMsgContext("bread");
        assertEquals(reqData.getMsgContext(), "bread");
        handler.send(
            doc,
            reqData,
            actionList,
            true
        );
        assertEquals(reqData.getMsgContext(), "crumb");

        if (LOG.isDebugEnabled()) {
            LOG.debug("Message:");
            String outputString =
                XMLUtils.prettyDocumentToString(doc);
            LOG.debug(outputString);
        }
    }

}
