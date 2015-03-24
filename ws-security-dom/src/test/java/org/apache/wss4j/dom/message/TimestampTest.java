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

package org.apache.wss4j.dom.message;

import java.text.DateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Locale;

import org.apache.wss4j.common.bsp.BSPEnforcer;
import org.apache.wss4j.common.bsp.BSPRule;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.util.WSTimeSource;
import org.apache.wss4j.common.util.XMLUtils;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.WSSConfig;
import org.apache.wss4j.dom.WSSecurityEngine;
import org.apache.wss4j.dom.WSSecurityEngineResult;
import org.apache.wss4j.dom.common.SOAPUtil;
import org.apache.wss4j.dom.common.SecurityTestUtil;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.message.token.Timestamp;
import org.apache.wss4j.dom.util.WSSecurityUtil;
import org.apache.wss4j.dom.util.XmlSchemaDateFormat;
import org.apache.wss4j.dom.validate.NoOpValidator;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * WS-Security Test Case for Timestamps.
 */
public class TimestampTest extends org.junit.Assert {
    private static final org.slf4j.Logger LOG = 
        org.slf4j.LoggerFactory.getLogger(TimestampTest.class);

    
    @org.junit.AfterClass
    public static void cleanup() throws Exception {
        SecurityTestUtil.cleanup();
    }
    
    /**
     * This is a test for processing a valid Timestamp.
     */
    @org.junit.Test
    public void testValidTimestamp() throws Exception {

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        WSSecTimestamp timestamp = new WSSecTimestamp();
        timestamp.setTimeToLive(300);
        Document createdDoc = timestamp.build(doc, secHeader);

        if (LOG.isDebugEnabled()) {
            String outputString = 
                XMLUtils.PrettyDocumentToString(createdDoc);
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
        
        Timestamp clone = new Timestamp(receivedTimestamp.getElement(), new BSPEnforcer(true));
        assertTrue(clone.equals(receivedTimestamp));
        assertTrue(clone.hashCode() == receivedTimestamp.hashCode());
    }
    
    
    /**
     * This is a test for processing a valid Timestamp with no expires element
     */
    @org.junit.Test
    public void testValidTimestampNoExpires() throws Exception {

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        WSSecTimestamp timestamp = new WSSecTimestamp();
        timestamp.setTimeToLive(0);
        Document createdDoc = timestamp.build(doc, secHeader);

        if (LOG.isDebugEnabled()) {
            String outputString = 
                XMLUtils.PrettyDocumentToString(createdDoc);
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
    @org.junit.Test
    public void testExpiredTimestamp() throws Exception {

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        WSSecTimestamp timestamp = new WSSecTimestamp();
        timestamp.setTimeToLive(-1);
        Document createdDoc = timestamp.build(doc, secHeader);

        if (LOG.isDebugEnabled()) {
            String outputString = 
                XMLUtils.PrettyDocumentToString(createdDoc);
            LOG.debug(outputString);
        }
        
        try {
            verify(createdDoc, WSSConfig.getNewInstance());
            fail("Expected failure on an expired timestamp");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.MESSAGE_EXPIRED); 
        }        
    }
    
    
    /**
     * This is a test for processing an "old" Timestamp, i.e. one with a "Created" element that is
     * out of date
     */
    @org.junit.Test
    public void testOldTimestamp() throws Exception {
        
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        WSSecTimestamp timestamp = new WSSecTimestamp();
        Document createdDoc = timestamp.build(doc, secHeader);

        if (LOG.isDebugEnabled()) {
            String outputString = 
                XMLUtils.PrettyDocumentToString(createdDoc);
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
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.MESSAGE_EXPIRED); 
        }  
    }
    
    
    /**
     * This is a test for processing an Timestamp where the "Created" element is in the (near)
     * future. It should be accepted by default when it is created 30 seconds in the future, 
     * and then rejected once we configure "0 seconds" for future-time-to-live.
     */
    @org.junit.Test
    public void testNearFutureCreated() throws Exception {
        
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        Element timestampElement = 
            doc.createElementNS(
                WSConstants.WSU_NS, WSConstants.WSU_PREFIX + ":" + WSConstants.TIMESTAMP_TOKEN_LN
            );

        DateFormat zulu = new XmlSchemaDateFormat();
        Element elementCreated =
            doc.createElementNS(
                WSConstants.WSU_NS, WSConstants.WSU_PREFIX + ":" + WSConstants.CREATED_LN
            );
        Date createdDate = new Date();
        long currentTime = createdDate.getTime() + 30000;
        createdDate.setTime(currentTime);
        elementCreated.appendChild(doc.createTextNode(zulu.format(createdDate)));
        timestampElement.appendChild(elementCreated);

        secHeader.getSecurityHeader().appendChild(timestampElement);
        
        if (LOG.isDebugEnabled()) {
            String outputString = 
                XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }
        //
        // Do some processing
        //
        WSSConfig config = WSSConfig.getNewInstance();
        verify(doc, config);
        try {
            config.setTimeStampFutureTTL(0);
            verify(doc, config);
            fail("The timestamp validation should have failed");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.MESSAGE_EXPIRED); 
        }
    }
    
    /**
     * This is a test for processing an Timestamp where the "Created" element is in the future.
     * A Timestamp that is 120 seconds in the future should be rejected by default.
     */
    @org.junit.Test
    public void testFutureCreated() throws Exception {
        
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        Element timestampElement = 
            doc.createElementNS(
                WSConstants.WSU_NS, WSConstants.WSU_PREFIX + ":" + WSConstants.TIMESTAMP_TOKEN_LN
            );

        DateFormat zulu = new XmlSchemaDateFormat();
        Element elementCreated =
            doc.createElementNS(
                WSConstants.WSU_NS, WSConstants.WSU_PREFIX + ":" + WSConstants.CREATED_LN
            );
        Date createdDate = new Date();
        long currentTime = createdDate.getTime() + 120000;
        createdDate.setTime(currentTime);
        elementCreated.appendChild(doc.createTextNode(zulu.format(createdDate)));
        timestampElement.appendChild(elementCreated);

        secHeader.getSecurityHeader().appendChild(timestampElement);
        
        if (LOG.isDebugEnabled()) {
            String outputString = 
                XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }
        //
        // Do some processing
        //
        WSSConfig config = WSSConfig.getNewInstance();
        try {
            verify(doc, config);
            fail("The timestamp validation should have failed");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.MESSAGE_EXPIRED); 
        }
    }
    
    
    /**
     * This is a test for processing an Timestamp where the "Created" element is greater than
     * the expiration time.
     */
    @org.junit.Test
    public void testExpiresBeforeCreated() throws Exception {
        
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        Element timestampElement = 
            doc.createElementNS(
                WSConstants.WSU_NS, WSConstants.WSU_PREFIX + ":" + WSConstants.TIMESTAMP_TOKEN_LN
            );

        DateFormat zulu = new XmlSchemaDateFormat();
        Element elementCreated =
            doc.createElementNS(
                WSConstants.WSU_NS, WSConstants.WSU_PREFIX + ":" + WSConstants.CREATED_LN
            );
        Date createdDate = new Date();
        long currentTime = createdDate.getTime();
        createdDate.setTime(currentTime);
        elementCreated.appendChild(doc.createTextNode(zulu.format(createdDate)));
        timestampElement.appendChild(elementCreated);
        
        Date expiresDate = new Date();
        expiresDate.setTime(expiresDate.getTime() - 300000);

        Element elementExpires =
            doc.createElementNS(
                WSConstants.WSU_NS, WSConstants.WSU_PREFIX + ":" + WSConstants.EXPIRES_LN
            );
        elementExpires.appendChild(doc.createTextNode(zulu.format(expiresDate)));
        timestampElement.appendChild(elementExpires);

        secHeader.getSecurityHeader().appendChild(timestampElement);
        
        if (LOG.isDebugEnabled()) {
            String outputString = 
                XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }
        //
        // Do some processing
        //
        try {
            verify(doc, WSSConfig.getNewInstance());
            fail("The timestamp validation should have failed");
        } catch (WSSecurityException ex) {
            //
        }
    }
    
    /**
     * This is a test for processing multiple Timestamps in the security header
     */
    @org.junit.Test
    public void testMultipleTimestamps() throws Exception {

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        WSSecTimestamp timestamp = new WSSecTimestamp();
        timestamp.setTimeToLive(300);
        Document createdDoc = timestamp.build(doc, secHeader);
        
        timestamp = new WSSecTimestamp();
        timestamp.setTimeToLive(60);
        createdDoc = timestamp.build(doc, secHeader);

        if (LOG.isDebugEnabled()) {
            String outputString = 
                XMLUtils.PrettyDocumentToString(createdDoc);
            LOG.debug(outputString);
        }
        
        //
        // Do some processing
        //
        WSSConfig wssConfig = WSSConfig.getNewInstance();
        try {
            verify(createdDoc, wssConfig);
            fail("Expected failure on multiple timestamps");
        } catch (WSSecurityException ex) {
            // expected
        }
        
        verify(createdDoc, Collections.singletonList(BSPRule.R3227));
    }
    
    /**
     * This is a test for processing an Timestamp where it contains multiple "Created" elements.
     * This Timestamp should be rejected.
     */
    @org.junit.Test
    public void testMultipleCreated() throws Exception {
        
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        Element timestampElement = 
            doc.createElementNS(
                WSConstants.WSU_NS, WSConstants.WSU_PREFIX + ":" + WSConstants.TIMESTAMP_TOKEN_LN
            );

        DateFormat zulu = new XmlSchemaDateFormat();
        Element elementCreated =
            doc.createElementNS(
                WSConstants.WSU_NS, WSConstants.WSU_PREFIX + ":" + WSConstants.CREATED_LN
            );
        Date createdDate = new Date();
        elementCreated.appendChild(doc.createTextNode(zulu.format(createdDate)));
        timestampElement.appendChild(elementCreated);
        timestampElement.appendChild(elementCreated.cloneNode(true));

        secHeader.getSecurityHeader().appendChild(timestampElement);
        
        if (LOG.isDebugEnabled()) {
            String outputString = 
                XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }
        //
        // Do some processing
        //
        try {
            verify(doc, WSSConfig.getNewInstance());
            fail("The timestamp validation should have failed on multiple Created elements");
        } catch (WSSecurityException ex) {
            // expected
        }
        
        verify(doc, Collections.singletonList(BSPRule.R3203));
    }
    
    /**
     * This is a test for processing an Timestamp where it contains no "Created" element.
     * This Timestamp should be rejected.
     */
    @org.junit.Test
    public void testNoCreated() throws Exception {
        
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        Element timestampElement = 
            doc.createElementNS(
                WSConstants.WSU_NS, WSConstants.WSU_PREFIX + ":" + WSConstants.TIMESTAMP_TOKEN_LN
            );

        DateFormat zulu = new XmlSchemaDateFormat();
        Element elementCreated =
            doc.createElementNS(
                WSConstants.WSU_NS, WSConstants.WSU_PREFIX + ":" + WSConstants.EXPIRES_LN
            );
        Date createdDate = new Date();
        long currentTime = createdDate.getTime() + 300000;
        createdDate.setTime(currentTime);
        elementCreated.appendChild(doc.createTextNode(zulu.format(createdDate)));
        timestampElement.appendChild(elementCreated);

        secHeader.getSecurityHeader().appendChild(timestampElement);
        
        if (LOG.isDebugEnabled()) {
            String outputString = 
                XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }
        //
        // Do some processing
        //
        try {
            verify(doc, WSSConfig.getNewInstance());
            fail("The timestamp validation should have failed on no Created element");
        } catch (WSSecurityException ex) {
            // expected
        }
        
        List<BSPRule> rules = new ArrayList<>();
        rules.add(BSPRule.R3203);
        rules.add(BSPRule.R3221);
        verify(doc, rules);
    }
    
    /**
     * This is a test for processing an Timestamp where it contains multiple "Expires" elements.
     * This Timestamp should be rejected.
     */
    @org.junit.Test
    public void testMultipleExpires() throws Exception {
        
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        Element timestampElement = 
            doc.createElementNS(
                WSConstants.WSU_NS, WSConstants.WSU_PREFIX + ":" + WSConstants.TIMESTAMP_TOKEN_LN
            );
        
        DateFormat zulu = new XmlSchemaDateFormat();
        Element elementCreated =
            doc.createElementNS(
                WSConstants.WSU_NS, WSConstants.WSU_PREFIX + ":" + WSConstants.CREATED_LN
            );
        Date createdDate = new Date();
        long currentTime = createdDate.getTime();
        createdDate.setTime(currentTime);
        elementCreated.appendChild(doc.createTextNode(zulu.format(createdDate)));
        timestampElement.appendChild(elementCreated);

        zulu = new XmlSchemaDateFormat();
        Element elementExpires =
            doc.createElementNS(
                WSConstants.WSU_NS, WSConstants.WSU_PREFIX + ":" + WSConstants.EXPIRES_LN
            );
        createdDate.setTime(currentTime + 300000);
        elementExpires.appendChild(doc.createTextNode(zulu.format(createdDate)));
        timestampElement.appendChild(elementExpires);
        timestampElement.appendChild(elementExpires.cloneNode(true));

        secHeader.getSecurityHeader().appendChild(timestampElement);
        
        if (LOG.isDebugEnabled()) {
            String outputString = 
                XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }
        //
        // Do some processing
        //
        try {
            verify(doc, WSSConfig.getNewInstance());
            fail("The timestamp validation should have failed on multiple Expires elements");
        } catch (WSSecurityException ex) {
            // expected
        }
        
        verify(doc, Collections.singletonList(BSPRule.R3224));
    }
    
    /**
     * This is a test for processing an Timestamp where it contains an "Expires" element before
     * the Created element. This Timestamp should be rejected as per the BSP spec.
     */
    @org.junit.Test
    public void testExpiresInFrontOfCreated() throws Exception {
        
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        Element timestampElement = 
            doc.createElementNS(
                WSConstants.WSU_NS, WSConstants.WSU_PREFIX + ":" + WSConstants.TIMESTAMP_TOKEN_LN
            );

        DateFormat zulu = new XmlSchemaDateFormat();
        Element elementCreated =
            doc.createElementNS(
                WSConstants.WSU_NS, WSConstants.WSU_PREFIX + ":" + WSConstants.EXPIRES_LN
            );
        Date expiresDate = new Date();
        long currentTime = expiresDate.getTime() + 300000;
        expiresDate.setTime(currentTime);
        elementCreated.appendChild(doc.createTextNode(zulu.format(expiresDate)));
        timestampElement.appendChild(elementCreated);
        
        Element elementExpires =
            doc.createElementNS(
                WSConstants.WSU_NS, WSConstants.WSU_PREFIX + ":" + WSConstants.CREATED_LN
            );
        elementExpires.appendChild(doc.createTextNode(zulu.format(new Date())));
        timestampElement.appendChild(elementExpires);

        secHeader.getSecurityHeader().appendChild(timestampElement);
        
        if (LOG.isDebugEnabled()) {
            String outputString = 
                XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }
        //
        // Do some processing
        //
        try {
            verify(doc, WSSConfig.getNewInstance());
            fail("The timestamp validation should have failed");
        } catch (WSSecurityException ex) {
            // expected
        }
        
        verify(doc, Collections.singletonList(BSPRule.R3221));
    }
    
    
    /**
     * This is a test for processing an Timestamp where it contains a Created element with
     * seconds > 60. This should be rejected as per the BSP spec.
     */
    @org.junit.Test
    public void testCreatedSeconds() throws Exception {
        
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        Element timestampElement = 
            doc.createElementNS(
                WSConstants.WSU_NS, WSConstants.WSU_PREFIX + ":" + WSConstants.TIMESTAMP_TOKEN_LN
            );

        Element elementCreated =
            doc.createElementNS(
                WSConstants.WSU_NS, WSConstants.WSU_PREFIX + ":" + WSConstants.CREATED_LN
            );
        elementCreated.appendChild(doc.createTextNode("2011-02-08T13:13:84.535Z"));
        timestampElement.appendChild(elementCreated);

        secHeader.getSecurityHeader().appendChild(timestampElement);
        
        if (LOG.isDebugEnabled()) {
            String outputString = 
                XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }
        //
        // Do some processing - disable the validator to make sure that the Timestamp processor
        // is rejecting the Timestamp
        //
        WSSConfig wssConfig = WSSConfig.getNewInstance();
        wssConfig.setValidator(WSSecurityEngine.TIMESTAMP, new NoOpValidator());
        try {
            verify(doc, wssConfig);
            fail("The timestamp validation should have failed");
        } catch (WSSecurityException ex) {
            //assertTrue(ex.getMessage().contains("Unparseable date"));
        }
    }
    
    
    /**
     * This is a test for processing an Timestamp where it contains a Created element with
     * a ValueType. This should be rejected as per the BSP spec.
     */
    @org.junit.Test
    public void testCreatedValueType() throws Exception {
        
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        Element timestampElement = 
            doc.createElementNS(
                WSConstants.WSU_NS, WSConstants.WSU_PREFIX + ":" + WSConstants.TIMESTAMP_TOKEN_LN
            );

        DateFormat zulu = new XmlSchemaDateFormat();
        Element elementCreated =
            doc.createElementNS(
                WSConstants.WSU_NS, WSConstants.WSU_PREFIX + ":" + WSConstants.CREATED_LN
            );
        Date createdDate = new Date();
        long currentTime = createdDate.getTime() + 300000;
        createdDate.setTime(currentTime);
        elementCreated.appendChild(doc.createTextNode(zulu.format(createdDate)));
        elementCreated.setAttributeNS(null, "ValueType", WSConstants.WSS_SAML_KI_VALUE_TYPE);
        timestampElement.appendChild(elementCreated);

        secHeader.getSecurityHeader().appendChild(timestampElement);
        
        if (LOG.isDebugEnabled()) {
            String outputString = 
                XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }
        //
        // Do some processing
        //
        WSSConfig wssConfig = WSSConfig.getNewInstance();
        wssConfig.setValidator(WSSecurityEngine.TIMESTAMP, new NoOpValidator());
        try {
            verify(doc, WSSConfig.getNewInstance());
            fail("The timestamp validation should have failed");
        } catch (WSSecurityException ex) {
            //
        }
        
        // Now it should pass...
        verify(doc, wssConfig, Collections.singletonList(BSPRule.R3225));
    }
    


    /**
     * This is a test for processing an Timestamp where it contains a CustomElement. This should
     * be rejected as per the BSP spec.
     */
    @org.junit.Test
    public void testCustomElement() throws Exception {
        
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        Element timestampElement = 
            doc.createElementNS(
                WSConstants.WSU_NS, WSConstants.WSU_PREFIX + ":" + WSConstants.TIMESTAMP_TOKEN_LN
            );

        DateFormat zulu = new XmlSchemaDateFormat();
        Element elementCreated =
            doc.createElementNS(
                WSConstants.WSU_NS, WSConstants.WSU_PREFIX + ":" + WSConstants.CREATED_LN
            );
        Date createdDate = new Date();
        elementCreated.appendChild(doc.createTextNode(zulu.format(createdDate)));
        timestampElement.appendChild(elementCreated);
        
        Element elementExpires =
            doc.createElementNS(
                WSConstants.WSU_NS, WSConstants.WSU_PREFIX + ":" + WSConstants.EXPIRES_LN
            );
        createdDate.setTime(createdDate.getTime() + 300000);
        elementExpires.appendChild(doc.createTextNode(zulu.format(createdDate)));
        timestampElement.appendChild(elementExpires);
        
        Element elementCustom =
            doc.createElementNS(
                WSConstants.WSU_NS, WSConstants.WSU_PREFIX + ":" + "Custom"
            );
        timestampElement.appendChild(elementCustom);

        secHeader.getSecurityHeader().appendChild(timestampElement);
        
        if (LOG.isDebugEnabled()) {
            String outputString = 
                XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }
        //
        // Do some processing
        //
        try {
            verify(doc, WSSConfig.getNewInstance());
            fail("The timestamp validation should have failed");
        } catch (WSSecurityException ex) {
            //
        }
        
        // Now it should pass...
        verify(doc, Collections.singletonList(BSPRule.R3222));
    }
    
    /**
     * This is a test to create a "Spoofed" Timestamp (see WSS-441)
     */
    @org.junit.Test
    public void testSpoofedTimestamp() throws Exception {

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        WSSecTimestamp timestamp = new WSSecTimestamp();
        timestamp.setTimeToLive(300);
        
        WSSConfig config = WSSConfig.getNewInstance();
        WSTimeSource spoofedTimeSource = new WSTimeSource() {

            public Date now() {
                Date currentTime = new Date();
                currentTime.setTime(currentTime.getTime() - (500L * 1000L));
                return currentTime;
            }
            
        };
        config.setCurrentTime(spoofedTimeSource);
        
        timestamp.setWsConfig(config);
        Document createdDoc = timestamp.build(doc, secHeader);

        if (LOG.isDebugEnabled()) {
            String outputString = 
                XMLUtils.PrettyDocumentToString(createdDoc);
            LOG.debug(outputString);
        }
        
        //
        // Do some processing
        //
        try {
            verify(createdDoc, WSSConfig.getNewInstance());
            fail("Expected failure on an expired timestamp");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.MESSAGE_EXPIRED); 
        }
    }
    
    @org.junit.Test
    public void testTimestampNoMilliseconds() throws Exception {

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        WSSConfig wssConfig = WSSConfig.getNewInstance();
        wssConfig.setPrecisionInMilliSeconds(false);
        WSSecTimestamp timestamp = new WSSecTimestamp();
        timestamp.setWsConfig(wssConfig);
        timestamp.setTimeToLive(300);
        Document createdDoc = timestamp.build(doc, secHeader);

        if (LOG.isDebugEnabled()) {
            String outputString = 
                XMLUtils.PrettyDocumentToString(createdDoc);
            LOG.debug(outputString);
        }
        
        //
        // Do some processing
        //
        List<WSSecurityEngineResult> wsResult = verify(createdDoc, WSSConfig.getNewInstance());
        WSSecurityEngineResult actionResult = 
            WSSecurityUtil.fetchActionResult(wsResult, WSConstants.TS);
        assertTrue(actionResult != null);
    }
    
    @org.junit.Test
    public void testThaiLocaleVerification() throws Exception {
        
        Locale defaultLocale = Locale.getDefault();
        try {
            Locale.setDefault(new Locale("th", "TH"));
        
            Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
            WSSecHeader secHeader = new WSSecHeader();
            secHeader.insertSecurityHeader(doc);
            
            WSSecTimestamp timestamp = new WSSecTimestamp();
            timestamp.setTimeToLive(300);
            Document createdDoc = timestamp.build(doc, secHeader);
            
            //
            // Do some processing
            //
            List<WSSecurityEngineResult> wsResult = verify(createdDoc, WSSConfig.getNewInstance());
            WSSecurityEngineResult actionResult = 
                WSSecurityUtil.fetchActionResult(wsResult, WSConstants.TS);
            assertTrue(actionResult != null);
        } finally {
            Locale.setDefault(defaultLocale);
        }
    }
    
    /**
     * Verifies the soap envelope
     */
    private List<WSSecurityEngineResult> verify(
        Document doc, WSSConfig wssConfig
    ) throws Exception {
        WSSecurityEngine secEngine = new WSSecurityEngine();
        RequestData requestData = new RequestData();
        requestData.setWssConfig(wssConfig);
        return secEngine.processSecurityHeader(doc, "", requestData);
    }
    
    /**
     * Verifies the soap envelope
     */
    private List<WSSecurityEngineResult> verify(
        Document doc, List<BSPRule> ignoredRules
    ) throws Exception {
        WSSecurityEngine secEngine = new WSSecurityEngine();
        RequestData requestData = new RequestData();
        requestData.setIgnoredBSPRules(ignoredRules);
        return secEngine.processSecurityHeader(doc, "", requestData);
    }
    
    /**
     * Verifies the soap envelope
     */
    private List<WSSecurityEngineResult> verify(
        Document doc, WSSConfig wssConfig, List<BSPRule> ignoredRules
    ) throws Exception {
        WSSecurityEngine secEngine = new WSSecurityEngine();
        RequestData requestData = new RequestData();
        requestData.setWssConfig(wssConfig);
        requestData.setIgnoredBSPRules(ignoredRules);
        return secEngine.processSecurityHeader(doc, "", requestData);
    }
    
    
}
