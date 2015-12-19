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

package org.apache.wss4j.dom.message.token;

import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.common.SOAPUtil;
import org.apache.wss4j.dom.common.SecurityTestUtil;
import org.apache.wss4j.dom.engine.WSSConfig;
import org.apache.wss4j.dom.engine.WSSecurityEngine;
import org.apache.wss4j.dom.engine.WSSecurityEngineResult;
import org.apache.wss4j.dom.handler.WSHandlerResult;
import org.apache.wss4j.common.bsp.BSPEnforcer;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.crypto.CryptoType;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.token.BinarySecurity;
import org.apache.wss4j.common.token.PKIPathSecurity;
import org.apache.wss4j.common.token.X509Security;
import org.apache.wss4j.common.util.XMLUtils;
import org.apache.wss4j.dom.message.WSSecHeader;
import org.apache.wss4j.dom.util.WSSecurityUtil;
import org.junit.Test;
import org.w3c.dom.Document;

import java.security.cert.X509Certificate;

/**
 * This is a test for constructing and processing BinarySecurityTokens.
 */
public class BinarySecurityTokenTest extends org.junit.Assert {
    private static final org.slf4j.Logger LOG =
        org.slf4j.LoggerFactory.getLogger(BinarySecurityTokenTest.class);
    private Crypto crypto = null;

    @org.junit.AfterClass
    public static void cleanup() throws Exception {
        SecurityTestUtil.cleanup();
    }

    public BinarySecurityTokenTest() throws Exception {
        crypto = CryptoFactory.getInstance("wss40.properties");
    }

    /**
     * A unit test for an X.509 BinarySecurityToken
     */
    @Test
    public void testX509() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);

        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        X509Security bst = new X509Security(doc);
        CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
        cryptoType.setAlias("wss40");
        X509Certificate[] certs = crypto.getX509Certificates(cryptoType);
        bst.setX509Certificate(certs[0]);

        WSSecurityUtil.prependChildElement(secHeader.getSecurityHeader(), bst.getElement());

        if (LOG.isDebugEnabled()) {
            LOG.debug("BST output");
            String outputString =
                XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }

        WSSecurityEngine secEngine = new WSSecurityEngine();
        secEngine.setWssConfig(WSSConfig.getNewInstance());
        WSHandlerResult results =
            secEngine.processSecurityHeader(doc, null, null, crypto);

        WSSecurityEngineResult actionResult =
            results.getActionResults().get(WSConstants.BST).get(0);
        BinarySecurity token =
            (BinarySecurity)actionResult.get(WSSecurityEngineResult.TAG_BINARY_SECURITY_TOKEN);
        assertNotNull(token);

        BinarySecurity clone = new BinarySecurity(token.getElement(), new BSPEnforcer(true));
        assertTrue(clone.equals(token));
        assertTrue(clone.hashCode() == token.hashCode());
    }

    /**
     * A unit test for an PKIPath BinarySecurityToken
     */
    @Test
    public void testPKIPath() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);

        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        PKIPathSecurity bst = new PKIPathSecurity(doc);
        CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
        cryptoType.setAlias("wss40");
        X509Certificate[] certs = crypto.getX509Certificates(cryptoType);
        bst.setX509Certificates(certs, crypto);

        WSSecurityUtil.prependChildElement(secHeader.getSecurityHeader(), bst.getElement());

        if (LOG.isDebugEnabled()) {
            LOG.debug("PKIPath output");
            String outputString =
                XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }

        WSSecurityEngine secEngine = new WSSecurityEngine();
        secEngine.setWssConfig(WSSConfig.getNewInstance());
        WSHandlerResult results =
            secEngine.processSecurityHeader(doc, null, null, crypto);

        WSSecurityEngineResult actionResult =
            results.getActionResults().get(WSConstants.BST).get(0);
        PKIPathSecurity token =
            (PKIPathSecurity)actionResult.get(WSSecurityEngineResult.TAG_BINARY_SECURITY_TOKEN);
        assertNotNull(token);
    }

    /**
     * A unit test for a custom BinarySecurityToken
     */
    @Test
    public void testCustomToken() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);

        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        BinarySecurity bst = new BinarySecurity(doc);
        bst.setToken("12435677".getBytes());

        WSSecurityUtil.prependChildElement(secHeader.getSecurityHeader(), bst.getElement());

        if (LOG.isDebugEnabled()) {
            LOG.debug("Custom Token output");
            String outputString =
                XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }

        WSSecurityEngine secEngine = new WSSecurityEngine();
        secEngine.setWssConfig(WSSConfig.getNewInstance());
        // Processing should fail as we have no ValueType attribute
        try {
            secEngine.processSecurityHeader(doc, null, null, crypto);
            fail("Expected failure on no ValueType");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.INVALID_SECURITY);
        }

        doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        bst = new BinarySecurity(doc);
        bst.setToken("12435677".getBytes());
        bst.setValueType("http://custom_value_Type");
        secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();
        WSSecurityUtil.prependChildElement(secHeader.getSecurityHeader(), bst.getElement());

        WSHandlerResult results =
            secEngine.processSecurityHeader(doc, null, null, crypto);
        WSSecurityEngineResult actionResult =
            results.getActionResults().get(WSConstants.BST).get(0);
        BinarySecurity token =
            (BinarySecurity)actionResult.get(WSSecurityEngineResult.TAG_BINARY_SECURITY_TOKEN);
        assertNotNull(token);
    }

}
