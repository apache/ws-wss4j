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

package org.apache.ws.security.message;

import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.common.SOAPUtil;
import org.apache.ws.security.message.token.Timestamp;
import org.apache.ws.security.util.WSSecurityUtil;
import org.apache.ws.security.util.XmlSchemaDateFormat;
import org.apache.ws.security.validate.NoOpValidator;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.text.DateFormat;
import java.util.Date;
import java.util.List;

/**
 * WS-Security Test Case for Timestamps.
 */
public class TimestampTest extends org.junit.Assert {
    private static final org.apache.commons.logging.Log LOG = 
        org.apache.commons.logging.LogFactory.getLog(TimestampTest.class);

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
        
        Timestamp clone = new Timestamp(receivedTimestamp.getElement());
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
    @org.junit.Test
    public void testOldTimestamp() throws Exception {
        
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
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
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
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
            assertTrue(ex.getErrorCode() == WSSecurityException.MESSAGE_EXPIRED); 
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
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
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
            assertTrue(ex.getErrorCode() == WSSecurityException.MESSAGE_EXPIRED); 
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
        long currentTime = createdDate.getTime() + 300000;
        createdDate.setTime(currentTime);
        elementCreated.appendChild(doc.createTextNode(zulu.format(createdDate)));
        timestampElement.appendChild(elementCreated);
        
        Date expiresDate = new Date();
        expiresDate.setTime(expiresDate.getTime() -300000);

        Element elementExpires =
            doc.createElementNS(
                WSConstants.WSU_NS, WSConstants.WSU_PREFIX + ":" + WSConstants.EXPIRES_LN
            );
        elementExpires.appendChild(doc.createTextNode(zulu.format(expiresDate)));
        timestampElement.appendChild(elementExpires);

        secHeader.getSecurityHeader().appendChild(timestampElement);
        
        if (LOG.isDebugEnabled()) {
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }
        //
        // Do some processing
        //
        try {
            verify(doc, WSSConfig.getNewInstance());
            fail("The timestamp validation should have failed");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.MESSAGE_EXPIRED); 
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
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(createdDoc);
            LOG.debug(outputString);
        }
        
        //
        // Do some processing
        //
        WSSConfig wssConfig = WSSConfig.getNewInstance();
        wssConfig.setWsiBSPCompliant(true);
        try {
            verify(createdDoc, wssConfig);
            fail("Expected failure on multiple timestamps");
        } catch (WSSecurityException ex) {
            // expected
        }
        
        // Turn off BSP compliance and the test should pass
        wssConfig.setWsiBSPCompliant(false);
        verify(createdDoc, wssConfig);
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
        long currentTime = createdDate.getTime() + 300000;
        createdDate.setTime(currentTime);
        elementCreated.appendChild(doc.createTextNode(zulu.format(createdDate)));
        timestampElement.appendChild(elementCreated);
        timestampElement.appendChild(elementCreated.cloneNode(true));

        secHeader.getSecurityHeader().appendChild(timestampElement);
        
        if (LOG.isDebugEnabled()) {
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
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
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }
        //
        // Do some processing
        //
        WSSConfig wssConfig = WSSConfig.getNewInstance();
        wssConfig.setWsiBSPCompliant(true);
        try {
            verify(doc, wssConfig);
            fail("The timestamp validation should have failed on no Created element");
        } catch (WSSecurityException ex) {
            // expected
        }
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
                WSConstants.WSU_NS, WSConstants.WSU_PREFIX + ":" + WSConstants.EXPIRES_LN
            );
        Date createdDate = new Date();
        long currentTime = createdDate.getTime() + 300000;
        createdDate.setTime(currentTime);
        elementCreated.appendChild(doc.createTextNode(zulu.format(createdDate)));
        timestampElement.appendChild(elementCreated);
        timestampElement.appendChild(elementCreated.cloneNode(true));

        secHeader.getSecurityHeader().appendChild(timestampElement);
        
        if (LOG.isDebugEnabled()) {
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
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
        Date createdDate = new Date();
        long currentTime = createdDate.getTime() + 300000;
        createdDate.setTime(currentTime);
        elementCreated.appendChild(doc.createTextNode(zulu.format(createdDate)));
        timestampElement.appendChild(elementCreated);
        
        Element elementExpires =
            doc.createElementNS(
                WSConstants.WSU_NS, WSConstants.WSU_PREFIX + ":" + WSConstants.CREATED_LN
            );
        elementExpires.appendChild(doc.createTextNode(zulu.format(createdDate)));
        timestampElement.appendChild(elementExpires);

        secHeader.getSecurityHeader().appendChild(timestampElement);
        
        if (LOG.isDebugEnabled()) {
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }
        //
        // Do some processing
        //
        WSSConfig wssConfig = WSSConfig.getNewInstance();
        wssConfig.setWsiBSPCompliant(true);
        try {
            verify(doc, wssConfig);
            fail("The timestamp validation should have failed");
        } catch (WSSecurityException ex) {
            // expected
        }
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
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }
        //
        // Do some processing - disable the validator to make sure that the Timestamp processor
        // is rejecting the Timestamp
        //
        WSSConfig wssConfig = WSSConfig.getNewInstance();
        wssConfig.setWsiBSPCompliant(true);
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
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }
        //
        // Do some processing
        //
        WSSConfig wssConfig = WSSConfig.getNewInstance();
        wssConfig.setWsiBSPCompliant(true);
        wssConfig.setValidator(WSSecurityEngine.TIMESTAMP, new NoOpValidator());
        try {
            verify(doc, wssConfig);
            fail("The timestamp validation should have failed");
        } catch (WSSecurityException ex) {
            //
        }
        
        // Now it should pass...
        wssConfig.setWsiBSPCompliant(false);
        verify(doc, wssConfig);
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
                WSConstants.WSU_NS, WSConstants.WSU_PREFIX + ":" + WSConstants.EXPIRES_LN
            );
        Date createdDate = new Date();
        long currentTime = createdDate.getTime() + 300000;
        createdDate.setTime(currentTime);
        elementCreated.appendChild(doc.createTextNode(zulu.format(createdDate)));
        timestampElement.appendChild(elementCreated);
        
        Element elementCustom =
            doc.createElementNS(
                WSConstants.WSU_NS, WSConstants.WSU_PREFIX + ":" + "Custom"
            );
        timestampElement.appendChild(elementCustom);

        secHeader.getSecurityHeader().appendChild(timestampElement);
        
        if (LOG.isDebugEnabled()) {
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }
        //
        // Do some processing
        //
        WSSConfig wssConfig = WSSConfig.getNewInstance();
        wssConfig.setWsiBSPCompliant(true);
        try {
            verify(doc, wssConfig);
            fail("The timestamp validation should have failed");
        } catch (WSSecurityException ex) {
            //
        }
        
        // Now it should pass...
        wssConfig.setWsiBSPCompliant(false);
        verify(doc, wssConfig);
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
        WSSecurityEngine secEngine = new WSSecurityEngine();
        secEngine.setWssConfig(wssConfig);
        return secEngine.processSecurityHeader(doc, null, null, null);
    }
    
    
}
