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

import javax.xml.crypto.dsig.SignatureMethod;

import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.WSSecurityEngine;
import org.apache.wss4j.dom.WSSecurityEngineResult;
import org.apache.wss4j.dom.common.SecretKeyCallbackHandler;
import org.apache.wss4j.dom.common.SOAPUtil;
import org.apache.wss4j.dom.common.SecurityTestUtil;
import org.apache.wss4j.dom.handler.WSHandlerResult;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.derivedKey.ConversationConstants;
import org.apache.wss4j.common.util.XMLUtils;
import org.apache.wss4j.dom.message.token.SecurityContextToken;
import org.apache.wss4j.dom.util.WSSecurityUtil;
import org.w3c.dom.Document;

/**
 * A set of tests for SecurityContextTokens.
 */
public class SecurityContextTokenTest extends org.junit.Assert {
    private static final org.slf4j.Logger LOG = 
        org.slf4j.LoggerFactory.getLogger(SecurityContextTokenTest.class);
    private WSSecurityEngine secEngine = new WSSecurityEngine();
    private SecretKeyCallbackHandler callbackHandler = new SecretKeyCallbackHandler();
    private Crypto crypto = null;
    
    public SecurityContextTokenTest() throws Exception {
        crypto = CryptoFactory.getInstance("wss40.properties");
    }

    @org.junit.AfterClass
    public static void cleanup() throws Exception {
        SecurityTestUtil.cleanup();
    }
    
    @org.junit.Test
    public void testBuild() {
        try {
            Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
            WSSecHeader secHeader = new WSSecHeader();
            secHeader.insertSecurityHeader(doc);

            WSSecSecurityContextToken sctBuilder = new WSSecSecurityContextToken();
            sctBuilder.prepare(doc, crypto);
            
            sctBuilder.prependSCTElementToHeader(doc, secHeader);

            String out = 
                XMLUtils.PrettyDocumentToString(doc);
            
            if (LOG.isDebugEnabled()) {
                LOG.debug(out);
            }

            assertTrue(
                "SecurityContextToken missing",
                out.indexOf(ConversationConstants.SECURITY_CONTEXT_TOKEN_LN) > 0
            );
            assertTrue(
                "wsc:Identifier missing", 
                out.indexOf(ConversationConstants.IDENTIFIER_LN) > 0
            );

        } catch (Exception e) {
            e.printStackTrace();
            fail(e.getMessage());
        }
    }

    /**
     * Test encryption using a derived key which is based on a secret associated
     * with a security context token
     */
    @org.junit.Test
    public void testSCTDKTEncrypt() {
        try {
            Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
            WSSecHeader secHeader = new WSSecHeader();
            secHeader.insertSecurityHeader(doc);

            WSSecSecurityContextToken sctBuilder = new WSSecSecurityContextToken();
            sctBuilder.prepare(doc, crypto);

            byte[] tempSecret = WSSecurityUtil.generateNonce(16);

            // Store the secret
            callbackHandler.addSecretKey(sctBuilder.getIdentifier(), tempSecret);

            String tokenId = sctBuilder.getSctId();

            // Derived key encryption
            WSSecDKEncrypt encrBuilder = new WSSecDKEncrypt();
            encrBuilder.setSymmetricEncAlgorithm(WSConstants.AES_128);
            encrBuilder.setExternalKey(tempSecret, tokenId);
            encrBuilder.build(doc, secHeader);

            sctBuilder.prependSCTElementToHeader(doc, secHeader);

            if (LOG.isDebugEnabled()) {
                String out = XMLUtils.PrettyDocumentToString(doc);
                LOG.debug(out);
            }

            WSHandlerResult results = verify(doc);
            
            WSSecurityEngineResult actionResult =
                results.getActionResults().get(WSConstants.SCT).get(0);
            SecurityContextToken receivedToken = 
                (SecurityContextToken) actionResult.get(WSSecurityEngineResult.TAG_SECURITY_CONTEXT_TOKEN);
            assertTrue(receivedToken != null);
            assertTrue(WSConstants.WSC_SCT_05_12.equals(receivedToken.getTokenType()));
            
            SecurityContextToken clone = new SecurityContextToken(receivedToken.getElement());
            assertTrue(clone.equals(receivedToken));
            assertTrue(clone.hashCode() == receivedToken.hashCode());
            
        } catch (Exception e) {
            e.printStackTrace();
            fail(e.getMessage());
        }
    }

    @org.junit.Test
    public void testSCTKDKTSign() {
        try {
            Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
            WSSecHeader secHeader = new WSSecHeader();
            secHeader.insertSecurityHeader(doc);

            WSSecSecurityContextToken sctBuilder = new WSSecSecurityContextToken();
            sctBuilder.setWscVersion(ConversationConstants.VERSION_05_12);
            sctBuilder.prepare(doc, crypto);

            byte[] tempSecret = WSSecurityUtil.generateNonce(16);

            // Store the secret
            callbackHandler.addSecretKey(sctBuilder.getIdentifier(), tempSecret);

            String tokenId = sctBuilder.getSctId();

            // Derived key signature
            WSSecDKSign sigBuilder = new WSSecDKSign();
            sigBuilder.setExternalKey(tempSecret, tokenId);
            sigBuilder.setSignatureAlgorithm(WSConstants.HMAC_SHA1);
            sigBuilder.build(doc, secHeader);
            
            sctBuilder.prependSCTElementToHeader(doc, secHeader);

            if (LOG.isDebugEnabled()) {
                String out = XMLUtils.PrettyDocumentToString(doc);
                LOG.debug(out);
            }

            WSHandlerResult results = verify(doc);
            
            WSSecurityEngineResult actionResult =
                results.getActionResults().get(WSConstants.SCT).get(0);
            SecurityContextToken receivedToken = 
                (SecurityContextToken) actionResult.get(WSSecurityEngineResult.TAG_SECURITY_CONTEXT_TOKEN);
            assertTrue(receivedToken != null);
            assertTrue(WSConstants.WSC_SCT_05_12.equals(receivedToken.getTokenType()));
            
        } catch (Exception e) {
            e.printStackTrace();
            fail(e.getMessage());
        }
    }
    
    /**
     * Test for WSS-217:
     * "Add ability to specify a reference to an absolute URI in the derived key functionality".
     */
    @org.junit.Test
    public void testSCTKDKTSignAbsolute() {
        try {
            Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
            WSSecHeader secHeader = new WSSecHeader();
            secHeader.insertSecurityHeader(doc);

            WSSecSecurityContextToken sctBuilder = new WSSecSecurityContextToken();
            sctBuilder.prepare(doc, crypto);

            byte[] tempSecret = WSSecurityUtil.generateNonce(16);

            // Store the secret
            callbackHandler.addSecretKey(sctBuilder.getIdentifier(), tempSecret);

            // Derived key signature
            WSSecDKSign sigBuilder = new WSSecDKSign();
            sigBuilder.setExternalKey(tempSecret, sctBuilder.getIdentifier());
            sigBuilder.setTokenIdDirectId(true);
            sigBuilder.setSignatureAlgorithm(WSConstants.HMAC_SHA1);
            sigBuilder.build(doc, secHeader);
            
            sctBuilder.prependSCTElementToHeader(doc, secHeader);

            if (LOG.isDebugEnabled()) {
                LOG.debug("DKT Absolute");
                String outputString = 
                    XMLUtils.PrettyDocumentToString(doc);
                LOG.debug(outputString);
            }

            verify(doc);
        } catch (Exception e) {
            e.printStackTrace();
            fail(e.getMessage());
        }
    }

    @org.junit.Test
    public void testSCTKDKTSignEncrypt() {
        try {
            Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
            WSSecHeader secHeader = new WSSecHeader();
            secHeader.insertSecurityHeader(doc);

            WSSecSecurityContextToken sctBuilder = new WSSecSecurityContextToken();
            sctBuilder.prepare(doc, crypto);

            byte[] tempSecret = WSSecurityUtil.generateNonce(16);

            // Store the secret
            callbackHandler.addSecretKey(sctBuilder.getIdentifier(), tempSecret);

            String tokenId = sctBuilder.getSctId();

            // Derived key signature
            WSSecDKSign sigBuilder = new WSSecDKSign();
            sigBuilder.setExternalKey(tempSecret, tokenId);
            sigBuilder.setSignatureAlgorithm(WSConstants.HMAC_SHA1);
            sigBuilder.build(doc, secHeader);

            // Derived key encryption
            WSSecDKEncrypt encrBuilder = new WSSecDKEncrypt();
            encrBuilder.setSymmetricEncAlgorithm(WSConstants.AES_128);
            encrBuilder.setExternalKey(tempSecret, tokenId);
            encrBuilder.build(doc, secHeader);

            sctBuilder.prependSCTElementToHeader(doc, secHeader);

            if (LOG.isDebugEnabled()) {
                String out = XMLUtils.PrettyDocumentToString(doc);
                LOG.debug(out);
            }

            verify(doc);
        } catch (Exception e) {
            e.printStackTrace();
            fail(e.getMessage());
        }
    }

    @org.junit.Test
    public void testSCTKDKTEncryptSign() {
        try {
            Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
            WSSecHeader secHeader = new WSSecHeader();
            secHeader.insertSecurityHeader(doc);

            WSSecSecurityContextToken sctBuilder = new WSSecSecurityContextToken();
            sctBuilder.prepare(doc, crypto);

            byte[] tempSecret = WSSecurityUtil.generateNonce(16);

            // Store the secret
            callbackHandler.addSecretKey(sctBuilder.getIdentifier(), tempSecret);

            String tokenId = sctBuilder.getSctId();

            // Derived key encryption
            WSSecDKEncrypt encrBuilder = new WSSecDKEncrypt();
            encrBuilder.setSymmetricEncAlgorithm(WSConstants.AES_128);
            encrBuilder.setExternalKey(tempSecret, tokenId);
            encrBuilder.build(doc, secHeader);

            // Derived key signature
            WSSecDKSign sigBuilder = new WSSecDKSign();
            sigBuilder.setExternalKey(tempSecret, tokenId);
            sigBuilder.setSignatureAlgorithm(WSConstants.HMAC_SHA1);
            sigBuilder.build(doc, secHeader);

            sctBuilder.prependSCTElementToHeader(doc, secHeader);

            if (LOG.isDebugEnabled()) {
                String out = XMLUtils.PrettyDocumentToString(doc);
                LOG.debug(out);
            }

            verify(doc);
        } catch (Exception e) {
            e.printStackTrace();
            fail(e.getMessage());
        }
    }
    
    /**
     * Test signature and verification using a SecurityContextToken directly,
     * rather than using a DerivedKeyToken to point to a SecurityContextToken.
     * See WSS-216 - https://issues.apache.org/jira/browse/WSS-216
     */
    @org.junit.Test
    public void testSCTSign() {
        try {
            Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
            WSSecHeader secHeader = new WSSecHeader();
            secHeader.insertSecurityHeader(doc);

            WSSecSecurityContextToken sctBuilder = new WSSecSecurityContextToken();
            sctBuilder.prepare(doc, crypto);

            byte[] tempSecret = WSSecurityUtil.generateNonce(16);

            // Store the secret
            callbackHandler.addSecretKey(sctBuilder.getIdentifier(), tempSecret);

            String tokenId = sctBuilder.getSctId();

            WSSecSignature builder = new WSSecSignature();
            builder.setSecretKey(tempSecret);
            builder.setKeyIdentifierType(WSConstants.CUSTOM_SYMM_SIGNING);
            builder.setCustomTokenValueType(WSConstants.WSC_SCT);
            builder.setCustomTokenId(tokenId);
            builder.setSignatureAlgorithm(SignatureMethod.HMAC_SHA1);
            builder.build(doc, crypto, secHeader);
            
            sctBuilder.prependSCTElementToHeader(doc, secHeader);
            
            if (LOG.isDebugEnabled()) {
                LOG.debug("SCT sign");
                String outputString = 
                    XMLUtils.PrettyDocumentToString(doc);
                LOG.debug(outputString);
            }

            verify(doc);
        } catch (Exception e) {
            e.printStackTrace();
            fail(e.getMessage());
        }
    }
    
    /**
     * Verifies the soap envelope <p/>
     * 
     * @param envelope
     * @throws Exception
     *             Thrown when there is a problem in verification
     */
    private WSHandlerResult verify(Document doc) throws Exception {
        WSHandlerResult results = 
            secEngine.processSecurityHeader(doc, null, callbackHandler, crypto);
        String outputString = 
            XMLUtils.PrettyDocumentToString(doc);
        assertTrue(outputString.indexOf("counter_port_type") > 0 ? true : false);
        return results;
    }


}
