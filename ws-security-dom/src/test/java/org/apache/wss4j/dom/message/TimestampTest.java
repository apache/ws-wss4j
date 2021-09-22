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

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

import org.apache.wss4j.common.bsp.BSPEnforcer;
import org.apache.wss4j.common.bsp.BSPRule;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.util.DateUtil;
import org.apache.wss4j.common.util.SOAPUtil;
import org.apache.wss4j.common.util.WSTimeSource;
import org.apache.wss4j.common.util.XMLUtils;
import org.apache.wss4j.dom.WSConstants;

import org.apache.wss4j.dom.engine.WSSConfig;
import org.apache.wss4j.dom.engine.WSSecurityEngine;
import org.apache.wss4j.dom.engine.WSSecurityEngineResult;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.handler.WSHandlerResult;
import org.apache.wss4j.dom.message.token.Timestamp;
import org.apache.wss4j.dom.validate.NoOpValidator;

import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * WS-Security Test Case for Timestamps.
 */
public class TimestampTest {
    private static final org.slf4j.Logger LOG =
        org.slf4j.LoggerFactory.getLogger(TimestampTest.class);

    /**
     * This is a test for processing a valid Timestamp.
     */
    @Test
    public void testValidTimestamp() throws Exception {

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecTimestamp timestamp = new WSSecTimestamp(secHeader);
        timestamp.setTimeToLive(300);
        Document createdDoc = timestamp.build();

        if (LOG.isDebugEnabled()) {
            String outputString =
                XMLUtils.prettyDocumentToString(createdDoc);
            LOG.debug(outputString);
        }

        //
        // Do some processing
        //
        WSHandlerResult wsResult = verify(createdDoc);
        WSSecurityEngineResult actionResult =
            wsResult.getActionResults().get(WSConstants.TS).get(0);
        assertNotNull(actionResult);

        Timestamp receivedTimestamp =
            (Timestamp)actionResult.get(WSSecurityEngineResult.TAG_TIMESTAMP);
        assertNotNull(receivedTimestamp);

        Timestamp clone = new Timestamp(receivedTimestamp.getElement(), new BSPEnforcer(true));
        assertTrue(clone.equals(receivedTimestamp));
        assertTrue(clone.hashCode() == receivedTimestamp.hashCode());
    }


    /**
     * This is a test for processing a valid Timestamp with no expires element
     */
    @Test
    public void testValidTimestampNoExpires() throws Exception {

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecTimestamp timestamp = new WSSecTimestamp(secHeader);
        timestamp.setTimeToLive(0);
        Document createdDoc = timestamp.build();

        if (LOG.isDebugEnabled()) {
            String outputString =
                XMLUtils.prettyDocumentToString(createdDoc);
            LOG.debug(outputString);
        }

        //
        // Do some processing
        //
        WSHandlerResult wsResult = verify(createdDoc);
        WSSecurityEngineResult actionResult =
            wsResult.getActionResults().get(WSConstants.TS).get(0);
        assertNotNull(actionResult);

        Timestamp receivedTimestamp =
            (Timestamp)actionResult.get(WSSecurityEngineResult.TAG_TIMESTAMP);
        assertNotNull(receivedTimestamp);
    }

    @Test
    public void testInvalidTimestampNoExpires() throws Exception {

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecTimestamp timestamp = new WSSecTimestamp(secHeader);
        timestamp.setTimeToLive(0);
        Document createdDoc = timestamp.build();

        if (LOG.isDebugEnabled()) {
            String outputString =
                XMLUtils.prettyDocumentToString(createdDoc);
            LOG.debug(outputString);
        }

        //
        // Do some processing
        //
        WSSecurityEngine secEngine = new WSSecurityEngine();
        RequestData requestData = new RequestData();
        requestData.setWssConfig(WSSConfig.getNewInstance());
        requestData.setRequireTimestampExpires(true);
        try {
            secEngine.processSecurityHeader(doc, requestData);
            fail("Failure expected on no Expires Element");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.SECURITY_ERROR);
        }

        requestData.setWssConfig(WSSConfig.getNewInstance());
        requestData.setRequireTimestampExpires(false);
        WSHandlerResult wsResult = secEngine.processSecurityHeader(doc, requestData);
        WSSecurityEngineResult actionResult =
            wsResult.getActionResults().get(WSConstants.TS).get(0);
        assertNotNull(actionResult);

        Timestamp receivedTimestamp =
            (Timestamp)actionResult.get(WSSecurityEngineResult.TAG_TIMESTAMP);
        assertNotNull(receivedTimestamp);
    }


    /**
     * This is a test for processing an expired Timestamp.
     */
    @Test
    public void testExpiredTimestamp() throws Exception {

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecTimestamp timestamp = new WSSecTimestamp(secHeader);
        timestamp.setTimeToLive(-1);
        Document createdDoc = timestamp.build();

        if (LOG.isDebugEnabled()) {
            String outputString =
                XMLUtils.prettyDocumentToString(createdDoc);
            LOG.debug(outputString);
        }

        try {
            verify(createdDoc);
            fail("Expected failure on an expired timestamp");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.MESSAGE_EXPIRED);
        }
    }


    /**
     * This is a test for processing an "old" Timestamp, i.e. one with a "Created" element that is
     * out of date
     */
    @Test
    public void testOldTimestamp() throws Exception {

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecTimestamp timestamp = new WSSecTimestamp(secHeader);
        Document createdDoc = timestamp.build();

        if (LOG.isDebugEnabled()) {
            String outputString =
                XMLUtils.prettyDocumentToString(createdDoc);
            LOG.debug(outputString);
        }

        //
        // Do some processing
        //
        RequestData requestData = new RequestData();
        requestData.setWssConfig(WSSConfig.getNewInstance());
        requestData.setTimeStampTTL(-1);
        try {
            verify(createdDoc, requestData);
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
    @Test
    public void testNearFutureCreated() throws Exception {

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        Element timestampElement =
            doc.createElementNS(
                WSConstants.WSU_NS, WSConstants.WSU_PREFIX + ":" + WSConstants.TIMESTAMP_TOKEN_LN
            );

        Element elementCreated =
            doc.createElementNS(
                WSConstants.WSU_NS, WSConstants.WSU_PREFIX + ":" + WSConstants.CREATED_LN
            );
        ZonedDateTime now = ZonedDateTime.now(ZoneOffset.UTC).plusSeconds(30L);
        elementCreated.appendChild(doc.createTextNode(DateUtil.getDateTimeFormatter(true).format(now)));
        timestampElement.appendChild(elementCreated);

        secHeader.getSecurityHeaderElement().appendChild(timestampElement);

        if (LOG.isDebugEnabled()) {
            String outputString =
                XMLUtils.prettyDocumentToString(doc);
            LOG.debug(outputString);
        }
        //
        // Do some processing
        //
        RequestData requestData = new RequestData();
        requestData.setWssConfig(WSSConfig.getNewInstance());
        requestData.setTimeStampFutureTTL(0);
        try {
            verify(doc, requestData);
            fail("The timestamp validation should have failed");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.MESSAGE_EXPIRED);
        }
    }

    /**
     * This is a test for processing an Timestamp where the "Created" element is in the future.
     * A Timestamp that is 120 seconds in the future should be rejected by default.
     */
    @Test
    public void testFutureCreated() throws Exception {

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        Element timestampElement =
            doc.createElementNS(
                WSConstants.WSU_NS, WSConstants.WSU_PREFIX + ":" + WSConstants.TIMESTAMP_TOKEN_LN
            );

        Element elementCreated =
            doc.createElementNS(
                WSConstants.WSU_NS, WSConstants.WSU_PREFIX + ":" + WSConstants.CREATED_LN
            );
        ZonedDateTime now = ZonedDateTime.now(ZoneOffset.UTC).plusSeconds(120L);
        elementCreated.appendChild(doc.createTextNode(DateUtil.getDateTimeFormatter(true).format(now)));
        timestampElement.appendChild(elementCreated);

        secHeader.getSecurityHeaderElement().appendChild(timestampElement);

        if (LOG.isDebugEnabled()) {
            String outputString =
                XMLUtils.prettyDocumentToString(doc);
            LOG.debug(outputString);
        }
        //
        // Do some processing
        //
        try {
            verify(doc);
            fail("The timestamp validation should have failed");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.MESSAGE_EXPIRED);
        }
    }


    /**
     * This is a test for processing an Timestamp where the "Created" element is greater than
     * the expiration time.
     */
    @Test
    public void testExpiresBeforeCreated() throws Exception {

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        Element timestampElement =
            doc.createElementNS(
                WSConstants.WSU_NS, WSConstants.WSU_PREFIX + ":" + WSConstants.TIMESTAMP_TOKEN_LN
            );

        Element elementCreated =
            doc.createElementNS(
                WSConstants.WSU_NS, WSConstants.WSU_PREFIX + ":" + WSConstants.CREATED_LN
            );
        ZonedDateTime now = ZonedDateTime.now(ZoneOffset.UTC);
        elementCreated.appendChild(doc.createTextNode(DateUtil.getDateTimeFormatter(true).format(now)));
        timestampElement.appendChild(elementCreated);

        Element elementExpires =
            doc.createElementNS(
                WSConstants.WSU_NS, WSConstants.WSU_PREFIX + ":" + WSConstants.EXPIRES_LN
            );
        now = now.minusSeconds(300L);
        elementExpires.appendChild(doc.createTextNode(DateUtil.getDateTimeFormatter(true).format(now)));
        timestampElement.appendChild(elementExpires);

        secHeader.getSecurityHeaderElement().appendChild(timestampElement);

        if (LOG.isDebugEnabled()) {
            String outputString =
                XMLUtils.prettyDocumentToString(doc);
            LOG.debug(outputString);
        }
        //
        // Do some processing
        //
        try {
            verify(doc);
            fail("The timestamp validation should have failed");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.MESSAGE_EXPIRED);
        }
    }

    /**
     * This is a test for processing multiple Timestamps in the security header
     */
    @Test
    public void testMultipleTimestamps() throws Exception {

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecTimestamp timestamp = new WSSecTimestamp(secHeader);
        timestamp.setTimeToLive(300);
        Document createdDoc = timestamp.build();

        timestamp = new WSSecTimestamp(secHeader);
        timestamp.setTimeToLive(60);
        createdDoc = timestamp.build();

        if (LOG.isDebugEnabled()) {
            String outputString =
                XMLUtils.prettyDocumentToString(createdDoc);
            LOG.debug(outputString);
        }

        //
        // Do some processing
        //
        try {
            verify(createdDoc);
            fail("Expected failure on multiple timestamps");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.INVALID_SECURITY);
        }

        verify(createdDoc, Collections.singletonList(BSPRule.R3227));
    }

    /**
     * This is a test for processing an Timestamp where it contains multiple "Created" elements.
     * This Timestamp should be rejected.
     */
    @Test
    public void testMultipleCreated() throws Exception {

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        Element timestampElement =
            doc.createElementNS(
                WSConstants.WSU_NS, WSConstants.WSU_PREFIX + ":" + WSConstants.TIMESTAMP_TOKEN_LN
            );

        Element elementCreated =
            doc.createElementNS(
                WSConstants.WSU_NS, WSConstants.WSU_PREFIX + ":" + WSConstants.CREATED_LN
            );
        ZonedDateTime now = ZonedDateTime.now(ZoneOffset.UTC);
        elementCreated.appendChild(doc.createTextNode(DateUtil.getDateTimeFormatter(true).format(now)));
        timestampElement.appendChild(elementCreated);
        timestampElement.appendChild(elementCreated.cloneNode(true));

        secHeader.getSecurityHeaderElement().appendChild(timestampElement);

        if (LOG.isDebugEnabled()) {
            String outputString =
                XMLUtils.prettyDocumentToString(doc);
            LOG.debug(outputString);
        }
        //
        // Do some processing
        //
        try {
            verify(doc);
            fail("The timestamp validation should have failed on multiple Created elements");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.INVALID_SECURITY);
        }

        verify(doc, Collections.singletonList(BSPRule.R3203));
    }

    /**
     * This is a test for processing an Timestamp where it contains no "Created" element.
     * This Timestamp should be rejected.
     */
    @Test
    public void testNoCreated() throws Exception {

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        Element timestampElement =
            doc.createElementNS(
                WSConstants.WSU_NS, WSConstants.WSU_PREFIX + ":" + WSConstants.TIMESTAMP_TOKEN_LN
            );

        Element elementExpires =
            doc.createElementNS(
                WSConstants.WSU_NS, WSConstants.WSU_PREFIX + ":" + WSConstants.EXPIRES_LN
            );
        ZonedDateTime now = ZonedDateTime.now(ZoneOffset.UTC).plusSeconds(300L);
        elementExpires.appendChild(doc.createTextNode(DateUtil.getDateTimeFormatter(true).format(now)));
        timestampElement.appendChild(elementExpires);

        secHeader.getSecurityHeaderElement().appendChild(timestampElement);

        if (LOG.isDebugEnabled()) {
            String outputString =
                XMLUtils.prettyDocumentToString(doc);
            LOG.debug(outputString);
        }
        //
        // Do some processing
        //
        try {
            verify(doc);
            fail("The timestamp validation should have failed on no Created element");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.INVALID_SECURITY);
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
    @Test
    public void testMultipleExpires() throws Exception {

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        Element timestampElement =
            doc.createElementNS(
                WSConstants.WSU_NS, WSConstants.WSU_PREFIX + ":" + WSConstants.TIMESTAMP_TOKEN_LN
            );

        Element elementCreated =
            doc.createElementNS(
                WSConstants.WSU_NS, WSConstants.WSU_PREFIX + ":" + WSConstants.CREATED_LN
            );
        ZonedDateTime now = ZonedDateTime.now(ZoneOffset.UTC);
        elementCreated.appendChild(doc.createTextNode(DateUtil.getDateTimeFormatter(true).format(now)));
        timestampElement.appendChild(elementCreated);

        Element elementExpires =
            doc.createElementNS(
                WSConstants.WSU_NS, WSConstants.WSU_PREFIX + ":" + WSConstants.EXPIRES_LN
            );
        now = now.plusSeconds(300L);
        elementExpires.appendChild(doc.createTextNode(DateUtil.getDateTimeFormatter(true).format(now)));
        timestampElement.appendChild(elementExpires);
        timestampElement.appendChild(elementExpires.cloneNode(true));

        secHeader.getSecurityHeaderElement().appendChild(timestampElement);

        if (LOG.isDebugEnabled()) {
            String outputString =
                XMLUtils.prettyDocumentToString(doc);
            LOG.debug(outputString);
        }
        //
        // Do some processing
        //
        try {
            verify(doc);
            fail("The timestamp validation should have failed on multiple Expires elements");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.INVALID_SECURITY);
        }

        verify(doc, Collections.singletonList(BSPRule.R3224));
    }

    /**
     * This is a test for processing an Timestamp where it contains an "Expires" element before
     * the Created element. This Timestamp should be rejected as per the BSP spec.
     */
    @Test
    public void testExpiresInFrontOfCreated() throws Exception {

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        Element timestampElement =
            doc.createElementNS(
                WSConstants.WSU_NS, WSConstants.WSU_PREFIX + ":" + WSConstants.TIMESTAMP_TOKEN_LN
            );

        Element elementCreated =
            doc.createElementNS(
                WSConstants.WSU_NS, WSConstants.WSU_PREFIX + ":" + WSConstants.EXPIRES_LN
            );
        ZonedDateTime now = ZonedDateTime.now(ZoneOffset.UTC).plusSeconds(300L);
        elementCreated.appendChild(doc.createTextNode(DateUtil.getDateTimeFormatter(true).format(now)));
        timestampElement.appendChild(elementCreated);

        Element elementExpires =
            doc.createElementNS(
                WSConstants.WSU_NS, WSConstants.WSU_PREFIX + ":" + WSConstants.CREATED_LN
            );
        now = ZonedDateTime.now(ZoneOffset.UTC);
        elementExpires.appendChild(doc.createTextNode(DateUtil.getDateTimeFormatter(true).format(now)));
        timestampElement.appendChild(elementExpires);

        secHeader.getSecurityHeaderElement().appendChild(timestampElement);

        if (LOG.isDebugEnabled()) {
            String outputString =
                XMLUtils.prettyDocumentToString(doc);
            LOG.debug(outputString);
        }
        //
        // Do some processing
        //
        try {
            verify(doc);
            fail("The timestamp validation should have failed");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.INVALID_SECURITY);
        }

        verify(doc, Collections.singletonList(BSPRule.R3221));
    }


    /**
     * This is a test for processing an Timestamp where it contains a Created element with
     * seconds > 60. This should be rejected as per the BSP spec.
     */
    @Test
    public void testCreatedSeconds() throws Exception {

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

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

        secHeader.getSecurityHeaderElement().appendChild(timestampElement);

        if (LOG.isDebugEnabled()) {
            String outputString =
                XMLUtils.prettyDocumentToString(doc);
            LOG.debug(outputString);
        }
        //
        // Do some processing - disable the validator to make sure that the Timestamp processor
        // is rejecting the Timestamp
        //
        WSSConfig wssConfig = WSSConfig.getNewInstance();
        wssConfig.setValidator(WSConstants.TIMESTAMP, new NoOpValidator());
        try {
            verify(doc, wssConfig, new ArrayList<>());
            fail("The timestamp validation should have failed");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.INVALID_SECURITY);
        }
    }


    /**
     * This is a test for processing an Timestamp where it contains a Created element with
     * a ValueType. This should be rejected as per the BSP spec.
     */
    @Test
    public void testCreatedValueType() throws Exception {

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        Element timestampElement =
            doc.createElementNS(
                WSConstants.WSU_NS, WSConstants.WSU_PREFIX + ":" + WSConstants.TIMESTAMP_TOKEN_LN
            );

        Element elementCreated =
            doc.createElementNS(
                WSConstants.WSU_NS, WSConstants.WSU_PREFIX + ":" + WSConstants.CREATED_LN
            );
        ZonedDateTime now = ZonedDateTime.now(ZoneOffset.UTC);
        elementCreated.appendChild(doc.createTextNode(DateUtil.getDateTimeFormatter(true).format(now)));
        elementCreated.setAttributeNS(null, "ValueType", WSConstants.WSS_SAML_KI_VALUE_TYPE);
        timestampElement.appendChild(elementCreated);

        secHeader.getSecurityHeaderElement().appendChild(timestampElement);

        if (LOG.isDebugEnabled()) {
            String outputString =
                XMLUtils.prettyDocumentToString(doc);
            LOG.debug(outputString);
        }
        //
        // Do some processing
        //
        try {
            verify(doc);
            fail("The timestamp validation should have failed");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.INVALID_SECURITY);
        }

        // Now it should pass...
        WSSConfig wssConfig = WSSConfig.getNewInstance();
        wssConfig.setValidator(WSConstants.TIMESTAMP, new NoOpValidator());
        verify(doc, wssConfig, Collections.singletonList(BSPRule.R3225));
    }



    /**
     * This is a test for processing an Timestamp where it contains a CustomElement. This should
     * be rejected as per the BSP spec.
     */
    @Test
    public void testCustomElement() throws Exception {

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        Element timestampElement =
            doc.createElementNS(
                WSConstants.WSU_NS, WSConstants.WSU_PREFIX + ":" + WSConstants.TIMESTAMP_TOKEN_LN
            );

        Element elementCreated =
            doc.createElementNS(
                WSConstants.WSU_NS, WSConstants.WSU_PREFIX + ":" + WSConstants.CREATED_LN
            );
        ZonedDateTime now = ZonedDateTime.now(ZoneOffset.UTC);
        elementCreated.appendChild(doc.createTextNode(DateUtil.getDateTimeFormatter(true).format(now)));
        timestampElement.appendChild(elementCreated);

        Element elementExpires =
            doc.createElementNS(
                WSConstants.WSU_NS, WSConstants.WSU_PREFIX + ":" + WSConstants.EXPIRES_LN
            );
        now = now.plusSeconds(300L);
        elementExpires.appendChild(doc.createTextNode(DateUtil.getDateTimeFormatter(true).format(now)));
        timestampElement.appendChild(elementExpires);

        Element elementCustom =
            doc.createElementNS(
                WSConstants.WSU_NS, WSConstants.WSU_PREFIX + ":" + "Custom"
            );
        timestampElement.appendChild(elementCustom);

        secHeader.getSecurityHeaderElement().appendChild(timestampElement);

        if (LOG.isDebugEnabled()) {
            String outputString =
                XMLUtils.prettyDocumentToString(doc);
            LOG.debug(outputString);
        }
        //
        // Do some processing
        //
        try {
            verify(doc);
            fail("The timestamp validation should have failed");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.INVALID_SECURITY);
        }

        // Now it should pass...
        verify(doc, Collections.singletonList(BSPRule.R3222));
    }

    /**
     * This is a test to create a "Spoofed" Timestamp (see WSS-441)
     */
    @Test
    public void testSpoofedTimestamp() throws Exception {

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecTimestamp timestamp = new WSSecTimestamp(secHeader);
        timestamp.setTimeToLive(300);

        WSTimeSource spoofedTimeSource = new WSTimeSource() {

            public Instant now() {
                return Instant.now().minusSeconds(500L);
            }

        };
        timestamp.setWsTimeSource(spoofedTimeSource);

        Document createdDoc = timestamp.build();

        if (LOG.isDebugEnabled()) {
            String outputString =
                XMLUtils.prettyDocumentToString(createdDoc);
            LOG.debug(outputString);
        }

        //
        // Do some processing
        //
        try {
            verify(createdDoc);
            fail("Expected failure on an expired timestamp");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.MESSAGE_EXPIRED);
        }
    }

    @Test
    public void testTimestampNoMilliseconds() throws Exception {

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecTimestamp timestamp = new WSSecTimestamp(secHeader);
        timestamp.setPrecisionInMilliSeconds(false);
        timestamp.setTimeToLive(300);
        Document createdDoc = timestamp.build();

        if (LOG.isDebugEnabled()) {
            String outputString =
                XMLUtils.prettyDocumentToString(createdDoc);
            LOG.debug(outputString);
        }

        //
        // Do some processing
        //
        WSHandlerResult wsResult = verify(createdDoc);
        WSSecurityEngineResult actionResult =
            wsResult.getActionResults().get(WSConstants.TS).get(0);
        assertNotNull(actionResult);
    }

    @Test
    public void testThaiLocaleVerification() throws Exception {

        Locale defaultLocale = Locale.getDefault();
        try {
            Locale.setDefault(new Locale("th", "TH"));

            Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
            WSSecHeader secHeader = new WSSecHeader(doc);
            secHeader.insertSecurityHeader();

            WSSecTimestamp timestamp = new WSSecTimestamp(secHeader);
            timestamp.setTimeToLive(300);
            Document createdDoc = timestamp.build();

            //
            // Do some processing
            //
            WSHandlerResult wsResult = verify(createdDoc);
            WSSecurityEngineResult actionResult =
                wsResult.getActionResults().get(WSConstants.TS).get(0);
            assertNotNull(actionResult);
        } finally {
            Locale.setDefault(defaultLocale);
        }
    }

    /**
     * Verifies the soap envelope
     */
    private WSHandlerResult verify(
        Document doc
    ) throws Exception {
        WSSecurityEngine secEngine = new WSSecurityEngine();
        RequestData requestData = new RequestData();
        requestData.setWssConfig(WSSConfig.getNewInstance());
        return secEngine.processSecurityHeader(doc, requestData);
    }

    private WSHandlerResult verify(
        Document doc, RequestData requestData
    ) throws Exception {
        WSSecurityEngine secEngine = new WSSecurityEngine();
        return secEngine.processSecurityHeader(doc, requestData);
    }

    /**
     * Verifies the soap envelope
     */
    private WSHandlerResult verify(
        Document doc, List<BSPRule> ignoredRules
    ) throws Exception {
        WSSecurityEngine secEngine = new WSSecurityEngine();
        RequestData requestData = new RequestData();
        requestData.setIgnoredBSPRules(ignoredRules);
        return secEngine.processSecurityHeader(doc, requestData);
    }

    /**
     * Verifies the soap envelope
     */
    private WSHandlerResult verify(
        Document doc, WSSConfig wssConfig, List<BSPRule> ignoredRules
    ) throws Exception {
        WSSecurityEngine secEngine = new WSSecurityEngine();
        RequestData requestData = new RequestData();
        requestData.setWssConfig(wssConfig);
        requestData.setIgnoredBSPRules(ignoredRules);
        return secEngine.processSecurityHeader(doc, requestData);
    }


}