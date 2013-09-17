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

import java.util.ArrayList;
import java.util.List;

import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.util.XMLUtils;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.WSSConfig;
import org.apache.wss4j.dom.WSSecurityEngine;
import org.apache.wss4j.dom.WSSecurityEngineResult;
import org.apache.wss4j.dom.common.CustomHandler;
import org.apache.wss4j.dom.common.KeystoreCallbackHandler;
import org.apache.wss4j.dom.common.SOAPUtil;
import org.apache.wss4j.dom.common.SecurityTestUtil;
import org.w3c.dom.Document;


/**
 * Some tests for WSHandlerConstants.USE_REQ_SIG_CERT - the user signature cert is used to
 * encrypt the response.
 */
public class UseReqSigCertTest extends org.junit.Assert {
    private static final org.slf4j.Logger LOG = 
        org.slf4j.LoggerFactory.getLogger(UseReqSigCertTest.class);
    
    @org.junit.AfterClass
    public static void cleanup() throws Exception {
        SecurityTestUtil.cleanup();
    }
    
    public UseReqSigCertTest() throws Exception {
        WSSConfig.init();
    }

    @org.junit.Test
    public void testIncludedCertificate() throws Exception {
        final WSSConfig cfg = WSSConfig.getNewInstance();
        final int action = WSConstants.SIGN | WSConstants.TS;
        final RequestData reqData = new RequestData();
        reqData.setWssConfig(cfg);
        reqData.setUsername("wss40");
        
        java.util.Map<String, Object> config = new java.util.TreeMap<String, Object>();
        config.put(WSHandlerConstants.SIG_PROP_FILE, "wss40.properties");
        config.put(WSHandlerConstants.SIG_KEY_ID, "DirectReference");
        config.put(WSHandlerConstants.PW_CALLBACK_REF, new KeystoreCallbackHandler());
        config.put(
            WSHandlerConstants.SIGNATURE_PARTS, "{}{" + WSConstants.WSU_NS + "}Timestamp"
        );
        reqData.setMsgContext(config);
        
        final java.util.List<Integer> actions = new java.util.ArrayList<Integer>();
        actions.add(WSConstants.SIGN);
        actions.add(WSConstants.TS);
        final Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        
        // Send the request
        CustomHandler handler = new CustomHandler();
        handler.send(
            action, 
            doc, 
            reqData, 
            actions,
            true
        );
        String outputString = 
            XMLUtils.PrettyDocumentToString(doc);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Signed message:");
            LOG.debug(outputString);
        }
        
        // Process the request
        List<WSSecurityEngineResult> results = processRequest(doc);
        WSHandlerResult rResult = new WSHandlerResult("", results);
        List<WSHandlerResult> handlerResults = new ArrayList<WSHandlerResult>();
        handlerResults.add(0, rResult);
        
        // Send the response
        sendResponse(handlerResults);
    }
    
    @org.junit.Test
    public void testIssuerSerial() throws Exception {
        final WSSConfig cfg = WSSConfig.getNewInstance();
        final int action = WSConstants.SIGN | WSConstants.TS;
        final RequestData reqData = new RequestData();
        reqData.setWssConfig(cfg);
        reqData.setUsername("wss40");
        
        java.util.Map<String, Object> config = new java.util.TreeMap<String, Object>();
        config.put(WSHandlerConstants.SIG_PROP_FILE, "wss40.properties");
        config.put(WSHandlerConstants.SIG_KEY_ID, "IssuerSerial");
        config.put(WSHandlerConstants.PW_CALLBACK_REF, new KeystoreCallbackHandler());
        config.put(
            WSHandlerConstants.SIGNATURE_PARTS, "{}{" + WSConstants.WSU_NS + "}Timestamp"
        );
        reqData.setMsgContext(config);
        
        final java.util.List<Integer> actions = new java.util.ArrayList<Integer>();
        actions.add(WSConstants.SIGN);
        actions.add(WSConstants.TS);
        final Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        
        // Send the request
        CustomHandler handler = new CustomHandler();
        handler.send(
            action, 
            doc, 
            reqData, 
            actions,
            true
        );
        String outputString = 
            XMLUtils.PrettyDocumentToString(doc);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Signed message:");
            LOG.debug(outputString);
        }
        
        // Process the request
        List<WSSecurityEngineResult> results = processRequest(doc);
        WSHandlerResult rResult = new WSHandlerResult("", results);
        List<WSHandlerResult> handlerResults = new ArrayList<WSHandlerResult>();
        handlerResults.add(0, rResult);
        
        // Send the response
        sendResponse(handlerResults);
    }
    
    @org.junit.Test
    public void testSKIKeyIdentifier() throws Exception {
        final WSSConfig cfg = WSSConfig.getNewInstance();
        final int action = WSConstants.SIGN | WSConstants.TS;
        final RequestData reqData = new RequestData();
        reqData.setWssConfig(cfg);
        reqData.setUsername("wss40");
        
        java.util.Map<String, Object> config = new java.util.TreeMap<String, Object>();
        config.put(WSHandlerConstants.SIG_PROP_FILE, "wss40.properties");
        config.put(WSHandlerConstants.SIG_KEY_ID, "SKIKeyIdentifier");
        config.put(WSHandlerConstants.PW_CALLBACK_REF, new KeystoreCallbackHandler());
        config.put(
            WSHandlerConstants.SIGNATURE_PARTS, "{}{" + WSConstants.WSU_NS + "}Timestamp"
        );
        reqData.setMsgContext(config);
        
        final java.util.List<Integer> actions = new java.util.ArrayList<Integer>();
        actions.add(WSConstants.SIGN);
        actions.add(WSConstants.TS);
        final Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        
        // Send the request
        CustomHandler handler = new CustomHandler();
        handler.send(
            action, 
            doc, 
            reqData, 
            actions,
            true
        );
        String outputString = 
            XMLUtils.PrettyDocumentToString(doc);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Signed message:");
            LOG.debug(outputString);
        }
        
        // Process the request
        List<WSSecurityEngineResult> results = processRequest(doc);
        WSHandlerResult rResult = new WSHandlerResult("", results);
        List<WSHandlerResult> handlerResults = new ArrayList<WSHandlerResult>();
        handlerResults.add(0, rResult);
        
        // Send the response
        sendResponse(handlerResults);
    }
    
    private List<WSSecurityEngineResult> processRequest(Document doc) throws WSSecurityException {
        final WSSConfig cfg = WSSConfig.getNewInstance();
        final int action = WSConstants.SIGN | WSConstants.TS;
        final RequestData reqData = new RequestData();
        reqData.setWssConfig(cfg);
        
        java.util.Map<String, Object> config = new java.util.TreeMap<String, Object>();
        config.put(WSHandlerConstants.SIG_VER_PROP_FILE, "wss40.properties");
        reqData.setMsgContext(config);
        
        CustomHandler handler = new CustomHandler();
        handler.receive(action, reqData);
        
        WSSecurityEngine securityEngine = new WSSecurityEngine();
        return securityEngine.processSecurityHeader(doc, "", reqData);
    }
    
    private void sendResponse(List<WSHandlerResult> handlerResults) throws Exception {
        final int action = WSConstants.ENCR;
        final RequestData reqData = new RequestData();
        
        java.util.Map<String, Object> config = new java.util.TreeMap<String, Object>();
        config.put(WSHandlerConstants.ENCRYPTION_USER, "useReqSigCert");
        config.put(WSHandlerConstants.RECV_RESULTS, handlerResults);
        reqData.setMsgContext(config);
        
        final java.util.List<Integer> actions = new java.util.ArrayList<Integer>();
        actions.add(WSConstants.ENCR);
        final Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        
        // Send message
        CustomHandler handler = new CustomHandler();
        handler.send(
            action, 
            doc, 
            reqData, 
            actions,
            true
        );
    }

}
