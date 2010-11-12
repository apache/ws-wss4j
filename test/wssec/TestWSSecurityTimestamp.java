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

package wssec;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.util.WSSecurityUtil;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.message.WSSecHeader;
import org.apache.ws.security.message.WSSecTimestamp;
import org.apache.ws.security.message.token.Timestamp;
import org.w3c.dom.Document;

import java.util.List;

/**
 * WS-Security Test Case for Timestamps.
 */
public class TestWSSecurityTimestamp extends TestCase {
    private static final Log LOG = LogFactory.getLog(TestWSSecurityTimestamp.class);
    private static final String SOAPMSG = 
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" 
        + "<SOAP-ENV:Envelope "
        +   "xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" "
        +   "xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" "
        +   "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">" 
        +   "<SOAP-ENV:Body>" 
        +       "<add xmlns=\"http://ws.apache.org/counter/counter_port_type\">" 
        +           "<value xmlns=\"\">15</value>" 
        +       "</add>" 
        +   "</SOAP-ENV:Body>" 
        + "</SOAP-ENV:Envelope>";
    
    private WSSecurityEngine secEngine = new WSSecurityEngine();

    /**
     * TestWSSecurity constructor
     * <p/>
     * 
     * @param name name of the test
     */
    public TestWSSecurityTimestamp(String name) {
        super(name);
    }

    /**
     * JUnit suite
     * <p/>
     * 
     * @return a junit test suite
     */
    public static Test suite() {
        return new TestSuite(TestWSSecurityTimestamp.class);
    }

    
    /**
     * This is a test for processing a valid Timestamp.
     */
    public void testValidTimestamp() throws Exception {

        Document doc = SOAPUtil.toSOAPPart(SOAPMSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        WSSecTimestamp timestamp = new WSSecTimestamp();
        timestamp.setTimeToLive(300);
        Document createdDoc = timestamp.build(doc, secHeader);

        if (LOG.isDebugEnabled()) {
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(createdDoc);
            LOG.debug(outputString);
        }
        
        //
        // Do some processing
        //
        List<WSSecurityEngineResult> wsResult = verify(createdDoc, WSSConfig.getNewInstance());
        WSSecurityEngineResult actionResult = 
            WSSecurityUtil.fetchActionResult(wsResult, WSConstants.TS);
        assertTrue(actionResult != null);
        
        Timestamp receivedTimestamp = 
            (Timestamp)actionResult.get(WSSecurityEngineResult.TAG_TIMESTAMP);
        assertTrue(receivedTimestamp != null);
    }
    
    
    /**
     * This is a test for processing a valid Timestamp with no expires element
     */
    public void testValidTimestampNoExpires() throws Exception {

        Document doc = SOAPUtil.toSOAPPart(SOAPMSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        WSSecTimestamp timestamp = new WSSecTimestamp();
        timestamp.setTimeToLive(0);
        Document createdDoc = timestamp.build(doc, secHeader);

        if (LOG.isDebugEnabled()) {
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(createdDoc);
            LOG.debug(outputString);
        }
        
        //
        // Do some processing
        //
        List<WSSecurityEngineResult> wsResult = verify(createdDoc, WSSConfig.getNewInstance());
        WSSecurityEngineResult actionResult = 
            WSSecurityUtil.fetchActionResult(wsResult, WSConstants.TS);
        assertTrue(actionResult != null);
        
        Timestamp receivedTimestamp = 
            (Timestamp)actionResult.get(WSSecurityEngineResult.TAG_TIMESTAMP);
        assertTrue(receivedTimestamp != null);
    }
    
    
    /**
     * This is a test for processing an expired Timestamp.
     */
    public void testExpiredTimestamp() throws Exception {

        Document doc = SOAPUtil.toSOAPPart(SOAPMSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        WSSecTimestamp timestamp = new WSSecTimestamp();
        timestamp.setTimeToLive(-1);
        Document createdDoc = timestamp.build(doc, secHeader);

        if (LOG.isDebugEnabled()) {
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(createdDoc);
            LOG.debug(outputString);
        }
        
        try {
            verify(createdDoc, WSSConfig.getNewInstance());
            fail("Expected failure on an expired timestamp");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.MESSAGE_EXPIRED); 
        }        
    }
    
    
    /**
     * This is a test for processing an "old" Timestamp, i.e. one with a "Created" element that is
     * out of date
     */
    public void testOldTimestamp() throws Exception {
        
        Document doc = SOAPUtil.toSOAPPart(SOAPMSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        WSSecTimestamp timestamp = new WSSecTimestamp();
        Document createdDoc = timestamp.build(doc, secHeader);

        if (LOG.isDebugEnabled()) {
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(createdDoc);
            LOG.debug(outputString);
        }
        
        //
        // Do some processing
        //
        WSSConfig wssConfig = WSSConfig.getNewInstance();
        wssConfig.setTimeStampTTL(-1);
        try {
            verify(createdDoc, wssConfig);
            fail("The timestamp validation should have failed");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.MESSAGE_EXPIRED); 
        }  
    }
    

    /**
     * Verifies the soap envelope
     * 
     * @param env soap envelope
     * @param wssConfig
     * @throws java.lang.Exception Thrown when there is a problem in verification
     */
    private List<WSSecurityEngineResult> verify(
        Document doc, WSSConfig wssConfig
    ) throws Exception {
        secEngine.setWssConfig(wssConfig);
        return secEngine.processSecurityHeader(doc, null, null, null);
    }
    
    
}
