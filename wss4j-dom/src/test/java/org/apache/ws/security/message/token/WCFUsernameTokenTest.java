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

package org.apache.ws.security.message.token;

import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.common.SOAPUtil;
import org.apache.ws.security.common.UsernamePasswordCallbackHandler;
import org.w3c.dom.Document;

import javax.security.auth.callback.CallbackHandler;


/**
 * A test-case for WSS-199 - "Add support for WCF non-standard Username Tokens"
 * (see also WSS-148 - "WCF interop issue: Namespace not honored incase of attributes.").
 * The issue is that WCF generated Username Tokens where the password type is namespace
 * qualified (incorrectly). WSS-199 added the ability to process these Username Tokens.
 */
public class WCFUsernameTokenTest extends org.junit.Assert {
    private static final org.apache.commons.logging.Log LOG = 
        org.apache.commons.logging.LogFactory.getLog(WCFUsernameTokenTest.class);
    private static final String SOAPUTMSG = 
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" 
        + "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" "
        + "xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" "
        + "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">"
        + "<SOAP-ENV:Header>"
        + "<wsse:Security SOAP-ENV:mustUnderstand=\"1\" "
        + "xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\">"
        + "<wsse:UsernameToken wsu:Id=\"UsernameToken-29477163\" xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">"
        + "<wsse:Username>wernerd</wsse:Username>"
        + "<wsse:Password " 
        + "wsse:Type=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText\">verySecret</wsse:Password>"
        + "</wsse:UsernameToken></wsse:Security></SOAP-ENV:Header>"
        + "<SOAP-ENV:Body>" 
        + "<add xmlns=\"http://ws.apache.org/counter/counter_port_type\">" 
        + "<value xmlns=\"\">15</value>" + "</add>" 
        + "</SOAP-ENV:Body>\r\n       \r\n" + "</SOAP-ENV:Envelope>";
    
    private WSSecurityEngine secEngine = new WSSecurityEngine();
    private CallbackHandler callbackHandler = new UsernamePasswordCallbackHandler();
    
    public WCFUsernameTokenTest() {
        WSSConfig config = WSSConfig.getNewInstance();
        config.setWsiBSPCompliant(false);
        secEngine.setWssConfig(config);
    }

    /**
     * Test that adds a UserNameToken with a namespace qualified type. This should fail
     * as WSS4J rejects these tokens by default.
     */
    @org.junit.Test
    public void testNamespaceQualifiedTypeRejected() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUTMSG);

        if (LOG.isDebugEnabled()) {
            LOG.debug("Message with UserNameToken PW Digest:");
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }
        try {
            verify(doc);
            fail("Failure expected on a bad password type");
        } catch (WSSecurityException ex) {
            // expected
        }
    }
    
    
    /**
     * Test that adds a UserNameToken with a namespace qualified type. This should pass
     * as WSS4J has been configured to accept these tokens.
     */
    @org.junit.Test
    public void testNamespaceQualifiedTypeAccepted() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUTMSG);

        if (LOG.isDebugEnabled()) {
            LOG.debug("Message with UserNameToken PW Digest:");
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }
        WSSConfig wssConfig = secEngine.getWssConfig();
        wssConfig.setAllowNamespaceQualifiedPasswordTypes(true);
        secEngine.setWssConfig(wssConfig);
        verify(doc);
    }
    
    
    /**
     * Verifies the soap envelope
     * 
     * @param env soap envelope
     * @throws java.lang.Exception Thrown when there is a problem in verification
     */
    private void verify(Document doc) throws Exception {
        LOG.info("Before verifying UsernameToken....");
        secEngine.processSecurityHeader(doc, null, callbackHandler, null);
        LOG.info("After verifying UsernameToken....");
    }

}
