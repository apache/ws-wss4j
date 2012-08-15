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

package org.apache.ws.security.misc;

import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.common.SOAPUtil;
import org.w3c.dom.Document;

/**
 * This tests how security headers are parsed and processed.
 */
public class SecurityHeaderTest extends org.junit.Assert {
    private static final String DUPLICATE_NULL_ACTOR_MSG = 
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" 
        + "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" "
        + "xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" "
        + "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">"
        + "<SOAP-ENV:Header>"
        + "<wsse:Security SOAP-ENV:mustUnderstand=\"1\" "
        + "xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\">"
        + "</wsse:Security>"
        + "<wsse:Security SOAP-ENV:mustUnderstand=\"1\" "
        + "xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\">"
        + "</wsse:Security>"
        + "</SOAP-ENV:Header>"
        + "<SOAP-ENV:Body>" 
        + "<add xmlns=\"http://ws.apache.org/counter/counter_port_type\">" 
        + "<value xmlns=\"\">15</value>" + "</add>" 
        + "</SOAP-ENV:Body>\r\n       \r\n" + "</SOAP-ENV:Envelope>";
    private static final String DUPLICATE_ACTOR_MSG = 
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" 
        + "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" "
        + "xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" "
        + "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">"
        + "<SOAP-ENV:Header>"
        + "<wsse:Security SOAP-ENV:actor=\"user\" SOAP-ENV:mustUnderstand=\"1\" "
        + "xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\">"
        + "</wsse:Security>"
        + "<wsse:Security SOAP-ENV:actor=\"user\" SOAP-ENV:mustUnderstand=\"1\" "
        + "xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\">"
        + "</wsse:Security>"
        + "</SOAP-ENV:Header>"
        + "<SOAP-ENV:Body>" 
        + "<add xmlns=\"http://ws.apache.org/counter/counter_port_type\">" 
        + "<value xmlns=\"\">15</value>" + "</add>" 
        + "</SOAP-ENV:Body>\r\n       \r\n" + "</SOAP-ENV:Envelope>";
    private static final String TWO_ACTOR_MSG = 
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" 
        + "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" "
        + "xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" "
        + "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">"
        + "<SOAP-ENV:Header>"
        + "<wsse:Security SOAP-ENV:mustUnderstand=\"1\" "
        + "xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\">"
        + "</wsse:Security>"
        + "<wsse:Security SOAP-ENV:actor=\"user\" SOAP-ENV:mustUnderstand=\"1\" "
        + "xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\">"
        + "</wsse:Security>"
        + "</SOAP-ENV:Header>"
        + "<SOAP-ENV:Body>" 
        + "<add xmlns=\"http://ws.apache.org/counter/counter_port_type\">" 
        + "<value xmlns=\"\">15</value>" + "</add>" 
        + "</SOAP-ENV:Body>\r\n       \r\n" + "</SOAP-ENV:Envelope>";
    
    private WSSecurityEngine secEngine = new WSSecurityEngine();

    /**
     * Test for processing multiple security headers with the same (null) actor
     */
    @org.junit.Test
    public void testDuplicateNullActor() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(DUPLICATE_NULL_ACTOR_MSG);
        try {
            secEngine.processSecurityHeader(doc, null, null, null);
            fail("Failure expected on a null actor");
        } catch (WSSecurityException ex) {
            // expected
        }
    }
    
    /**
     * Test for processing multiple security headers with the same actor
     */
    @org.junit.Test
    public void testDuplicateActor() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(DUPLICATE_ACTOR_MSG);
        try {
            secEngine.processSecurityHeader(doc, "user", null, null);
            fail("Failure expected on a duplicate actor");
        } catch (WSSecurityException ex) {
            // expected
        }
    }
    
    /**
     * Test for processing multiple security headers with different actors
     */
    @org.junit.Test
    public void testTwoActors() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(TWO_ACTOR_MSG);
        secEngine.processSecurityHeader(doc, null, null, null);
        
        secEngine.processSecurityHeader(doc, "user", null, null);
    }
}
