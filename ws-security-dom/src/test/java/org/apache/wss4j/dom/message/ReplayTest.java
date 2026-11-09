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

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.security.auth.callback.CallbackHandler;

import org.apache.wss4j.common.cache.EHCacheReplayCache;
import org.apache.wss4j.common.util.SOAPUtil;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.common.KeystoreCallbackHandler;
import org.apache.wss4j.dom.common.SAML2CallbackHandler;

import org.apache.wss4j.dom.common.UsernamePasswordCallbackHandler;
import org.apache.wss4j.dom.engine.WSSConfig;
import org.apache.wss4j.dom.engine.WSSecurityEngine;
import org.apache.wss4j.common.WSEncryptionPart;
import org.apache.wss4j.common.cache.MemoryReplayCache;
import org.apache.wss4j.common.cache.ReplayCache;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.crypto.CryptoType;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.saml.SAMLCallback;
import org.apache.wss4j.common.saml.SAMLUtil;
import org.apache.wss4j.common.saml.SamlAssertionWrapper;
import org.apache.wss4j.common.saml.bean.ConditionsBean;
import org.apache.wss4j.common.saml.builder.SAML2Constants;
import org.apache.wss4j.common.util.XMLUtils;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.handler.WSHandlerResult;
import org.apache.wss4j.dom.util.WSSecurityUtil;
import org.apache.wss4j.dom.validate.SamlAssertionValidator;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * Some test-cases for replay attacks.
 */
public class ReplayTest {
    private static final org.slf4j.Logger LOG =
        org.slf4j.LoggerFactory.getLogger(ReplayTest.class);

    private CallbackHandler callbackHandler = new KeystoreCallbackHandler();
    private Crypto crypto;

    @TempDir
    Path tempDir;

    public ReplayTest() throws Exception {
        crypto = CryptoFactory.getInstance();
    }

    private ReplayCache createCache(String key) throws WSSecurityException {
        return new EHCacheReplayCache(key, tempDir);
    }

    @Test
    public void testReplayedTimestamp() throws Exception {

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecTimestamp timestamp = new WSSecTimestamp(secHeader);
        timestamp.setTimeToLive(300);
        Document createdDoc = timestamp.build();

        WSSecSignature builder = new WSSecSignature(secHeader);
        builder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        builder.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);

        WSEncryptionPart encP =
            new WSEncryptionPart(
                "Timestamp", WSConstants.WSU_NS, "");
        builder.getParts().add(encP);

        builder.prepare(crypto);

        List<javax.xml.crypto.dsig.Reference> referenceList =
            builder.addReferencesToSign(builder.getParts());

        builder.computeSignature(referenceList, false, null);

        if (LOG.isDebugEnabled()) {
            String outputString =
                XMLUtils.prettyDocumentToString(createdDoc);
            LOG.debug(outputString);
        }

        WSSConfig wssConfig = WSSConfig.getNewInstance();
        RequestData data = new RequestData();
        data.setWssConfig(wssConfig);
        data.setCallbackHandler(callbackHandler);
        data.setTimestampReplayCache(new MemoryReplayCache());

        // Successfully verify timestamp
        verify(createdDoc, wssConfig, data);

        // Now try again - a replay attack should be detected
        try {
            verify(createdDoc, wssConfig, data);
            fail("Expected failure on a replay attack");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.INVALID_SECURITY);
        }
    }

    /**
     * A message whose Signature fails to validate must not leave its identifier in the replay
     * cache. Otherwise an attacker can take a genuine message, tamper with a signed part of it so
     * that the Signature no longer validates, and send that first: the tampered message is
     * rejected, but it has claimed the genuine message's replay cache identifier - the Timestamp,
     * SignatureValue and signing key are untouched - so the genuine message is then rejected as a
     * replay when it arrives.
     */
    @Test
    public void testReplayCacheNotPoisonedByInvalidSignature() throws Exception {

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecTimestamp timestamp = new WSSecTimestamp(secHeader);
        timestamp.setTimeToLive(300);
        Document createdDoc = timestamp.build();

        WSSecSignature builder = new WSSecSignature(secHeader);
        builder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        builder.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);

        // Sign the Timestamp and the SOAP Body. The Body is what gets tampered with below; the
        // Timestamp, SignatureValue and signing key - the values the replay cache identifier is
        // derived from - are left exactly as they are in the genuine message.
        builder.getParts().add(new WSEncryptionPart("Timestamp", WSConstants.WSU_NS, ""));
        builder.getParts().add(WSSecurityUtil.getDefaultEncryptionPart(createdDoc));

        builder.prepare(crypto);

        List<javax.xml.crypto.dsig.Reference> referenceList =
            builder.addReferencesToSign(builder.getParts());

        builder.computeSignature(referenceList, false, null);

        String genuineMessage = XMLUtils.prettyDocumentToString(createdDoc);
        if (LOG.isDebugEnabled()) {
            LOG.debug(genuineMessage);
        }

        String tamperedMessage = genuineMessage.replace(">15<", ">16<");
        assertNotEquals(genuineMessage, tamperedMessage, "The signed SOAP Body was not modified");

        WSSConfig wssConfig = WSSConfig.getNewInstance();
        RequestData data = new RequestData();
        data.setWssConfig(wssConfig);
        data.setCallbackHandler(callbackHandler);
        data.setTimestampReplayCache(new MemoryReplayCache());

        // The tampered message must be rejected, as its Signature no longer validates
        try {
            verify(SOAPUtil.toSOAPPart(tamperedMessage), wssConfig, data);
            fail("Expected failure on a tampered message");
        } catch (WSSecurityException ex) {
            assertEquals(WSSecurityException.ErrorCode.FAILED_CHECK, ex.getErrorCode());
        }

        // ...and it must not have cached the genuine message's identifier on its way out
        verify(SOAPUtil.toSOAPPart(genuineMessage), wssConfig, data);

        // Replay detection must still work for the genuine message itself
        try {
            verify(SOAPUtil.toSOAPPart(genuineMessage), wssConfig, data);
            fail("Expected failure on a replay attack");
        } catch (WSSecurityException ex) {
            assertEquals(WSSecurityException.ErrorCode.INVALID_SECURITY, ex.getErrorCode());
        }
    }

    /**
     * The replay cache identifier must be derived from the parsed Created value, not from the raw
     * text of the Created element. "Z" and "+00:00" denote the same instant, so a message whose
     * Created value has merely been rewritten from one to the other is a replay, and must be
     * rejected as one. Where the Signature does not cover the Timestamp - as here, only the SOAP
     * Body is signed - that rewriting costs an attacker nothing.
     */
    /**
     * An ECDSA SignatureValue (r, s) can be rewritten as (r, n - s), where n is the order of the
     * curve, without the private key, and still verifies. A replayed message rewritten that way
     * must still be detected, so the replay cache must not be keyed on the SignatureValue.
     */
    @Test
    public void testReplayedTimestampRewrittenECDSASignatureValue() throws Exception {
        Crypto ecCrypto = CryptoFactory.getInstance("wss40.properties");

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecTimestamp timestamp = new WSSecTimestamp(secHeader);
        timestamp.setTimeToLive(300);
        Document createdDoc = timestamp.build();

        WSSecSignature builder = new WSSecSignature(secHeader);
        builder.setUserInfo("wss40ec", "security");
        builder.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
        builder.setSignatureAlgorithm(WSConstants.ECDSA_SHA256);
        builder.getParts().add(new WSEncryptionPart("Timestamp", WSConstants.WSU_NS, ""));
        builder.prepare(ecCrypto);
        List<javax.xml.crypto.dsig.Reference> referenceList =
            builder.addReferencesToSign(builder.getParts());
        builder.computeSignature(referenceList, false, null);
        // The BinarySecurityToken the Signature refers to is only added to the header by build(),
        // so it must be added here too
        builder.prependBSTElementToHeader();

        ReplayCache replayCache = new MemoryReplayCache();
        verify(createdDoc, ecCrypto, replayCache);

        // Rewrite the SignatureValue (r, s) as (r, n - s)
        CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
        cryptoType.setAlias("wss40ec");
        X509Certificate[] certs = ecCrypto.getX509Certificates(cryptoType);
        BigInteger order = ((ECPublicKey)certs[0].getPublicKey()).getParams().getOrder();

        Element signatureValueElement =
            (Element)createdDoc.getElementsByTagNameNS(WSConstants.SIG_NS, "SignatureValue").item(0);
        byte[] signatureValue = Base64.getMimeDecoder().decode(signatureValueElement.getTextContent());
        int half = signatureValue.length / 2;
        byte[] s = new byte[half];
        System.arraycopy(signatureValue, half, s, 0, half);
        byte[] rewrittenS = order.subtract(new BigInteger(1, s)).toByteArray();
        byte[] rewritten = signatureValue.clone();
        java.util.Arrays.fill(rewritten, half, rewritten.length, (byte)0);
        int length = Math.min(rewrittenS.length, half);
        System.arraycopy(rewrittenS, rewrittenS.length - length, rewritten, rewritten.length - length, length);
        assertFalse(java.util.Arrays.equals(signatureValue, rewritten));
        signatureValueElement.setTextContent(Base64.getEncoder().encodeToString(rewritten));

        // The rewritten SignatureValue is a valid signature in its own right...
        verify(createdDoc, ecCrypto, new MemoryReplayCache());

        // ...but it is the same message, so it must be detected as a replay
        try {
            verify(createdDoc, ecCrypto, replayCache);
            fail("Expected failure on a replay attack");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.INVALID_SECURITY);
        }
    }

    private WSHandlerResult verify(Document doc, Crypto sigVerCrypto, ReplayCache replayCache) throws Exception {
        WSSConfig wssConfig = WSSConfig.getNewInstance();
        RequestData data = new RequestData();
        data.setWssConfig(wssConfig);
        data.setCallbackHandler(callbackHandler);
        data.setSigVerCrypto(sigVerCrypto);
        data.setTimestampReplayCache(replayCache);
        WSSecurityEngine secEngine = new WSSecurityEngine();
        secEngine.setWssConfig(wssConfig);
        return secEngine.processSecurityHeader(WSSecurityUtil.getSecurityHeader(doc, null), data);
    }

    @Test
    public void testReplayedTimestampWithEquivalentCreatedValue() throws Exception {

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecTimestamp timestamp = new WSSecTimestamp(secHeader);
        timestamp.setTimeToLive(300);
        Document createdDoc = timestamp.build();

        WSSecSignature builder = new WSSecSignature(secHeader);
        builder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        builder.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);

        // Sign the SOAP Body only, leaving the Timestamp unprotected
        builder.getParts().add(WSSecurityUtil.getDefaultEncryptionPart(createdDoc));

        builder.prepare(crypto);

        List<javax.xml.crypto.dsig.Reference> referenceList =
            builder.addReferencesToSign(builder.getParts());

        builder.computeSignature(referenceList, false, null);

        String genuineMessage = XMLUtils.prettyDocumentToString(createdDoc);
        if (LOG.isDebugEnabled()) {
            LOG.debug(genuineMessage);
        }

        // Rewrite the Created value's trailing "Z" as the equivalent "+00:00" offset. The
        // Signature still validates, as it does not cover the Timestamp.
        String replayedMessage =
            genuineMessage.replaceFirst("(<[^>]*Created[^>]*>[^<]*)Z(</)", "$1+00:00$2");
        assertNotEquals(genuineMessage, replayedMessage, "The Created value was not rewritten");

        WSSConfig wssConfig = WSSConfig.getNewInstance();
        RequestData data = new RequestData();
        data.setWssConfig(wssConfig);
        data.setCallbackHandler(callbackHandler);
        data.setTimestampReplayCache(new MemoryReplayCache());

        // Successfully verify the genuine message
        verify(SOAPUtil.toSOAPPart(genuineMessage), wssConfig, data);

        // The rewritten message denotes the same Created instant, so it is a replay
        try {
            verify(SOAPUtil.toSOAPPart(replayedMessage), wssConfig, data);
            fail("Expected failure on a replay attack");
        } catch (WSSecurityException ex) {
            assertEquals(WSSecurityException.ErrorCode.INVALID_SECURITY, ex.getErrorCode());
        }
    }

    @Test
    public void testEhCacheReplayedTimestamp() throws Exception {

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecTimestamp timestamp = new WSSecTimestamp(secHeader);
        timestamp.setTimeToLive(300);
        Document createdDoc = timestamp.build();

        WSSecSignature builder = new WSSecSignature(secHeader);
        builder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        builder.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);

        WSEncryptionPart encP =
            new WSEncryptionPart(
                "Timestamp", WSConstants.WSU_NS, "");
        builder.getParts().add(encP);

        builder.prepare(crypto);

        List<javax.xml.crypto.dsig.Reference> referenceList =
            builder.addReferencesToSign(builder.getParts());

        builder.computeSignature(referenceList, false, null);

        if (LOG.isDebugEnabled()) {
            String outputString =
                XMLUtils.prettyDocumentToString(createdDoc);
            LOG.debug(outputString);
        }

        WSSConfig wssConfig = WSSConfig.getNewInstance();
        RequestData data = new RequestData();
        data.setWssConfig(wssConfig);
        data.setCallbackHandler(callbackHandler);
        ReplayCache replayCache = createCache("wss4j.timestamp.cache-");
        data.setTimestampReplayCache(replayCache);

        // Successfully verify timestamp
        verify(createdDoc, wssConfig, data);

        // Now try again - a replay attack should be detected
        try {
            verify(createdDoc, wssConfig, data);
            fail("Expected failure on a replay attack");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.INVALID_SECURITY);
        }

        replayCache.close();
    }

    @Test
    public void testReplayedTimestampBelowSignature() throws Exception {

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecTimestamp timestamp = new WSSecTimestamp(secHeader);
        timestamp.setTimeToLive(300);
        Document createdDoc = timestamp.build();

        WSSecSignature builder = new WSSecSignature(secHeader);
        builder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        builder.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);

        WSEncryptionPart encP =
            new WSEncryptionPart(
                "Timestamp", WSConstants.WSU_NS, "");
        builder.getParts().add(encP);

        builder.build(crypto);

        if (LOG.isDebugEnabled()) {
            String outputString =
                XMLUtils.prettyDocumentToString(createdDoc);
            LOG.debug(outputString);
        }

        WSSConfig wssConfig = WSSConfig.getNewInstance();
        RequestData data = new RequestData();
        data.setWssConfig(wssConfig);
        data.setCallbackHandler(callbackHandler);
        data.setTimestampReplayCache(new MemoryReplayCache());

        // Successfully verify timestamp
        verify(createdDoc, wssConfig, data);

        // Now try again - a replay attack should be detected
        try {
            verify(createdDoc, wssConfig, data);
            fail("Expected failure on a replay attack");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.INVALID_SECURITY);
        }
    }

    @Test
    public void testEhCacheReplayedTimestampBelowSignature() throws Exception {

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecTimestamp timestamp = new WSSecTimestamp(secHeader);
        timestamp.setTimeToLive(300);
        Document createdDoc = timestamp.build();

        WSSecSignature builder = new WSSecSignature(secHeader);
        builder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        builder.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);

        WSEncryptionPart encP =
            new WSEncryptionPart(
                "Timestamp", WSConstants.WSU_NS, "");
        builder.getParts().add(encP);

        builder.build(crypto);

        if (LOG.isDebugEnabled()) {
            String outputString =
                XMLUtils.prettyDocumentToString(createdDoc);
            LOG.debug(outputString);
        }

        WSSConfig wssConfig = WSSConfig.getNewInstance();
        RequestData data = new RequestData();
        data.setWssConfig(wssConfig);
        data.setCallbackHandler(callbackHandler);
        ReplayCache replayCache = createCache("wss4j.timestamp.cache-");
        data.setTimestampReplayCache(replayCache);

        // Successfully verify timestamp
        verify(createdDoc, wssConfig, data);

        // Now try again - a replay attack should be detected
        try {
            verify(createdDoc, wssConfig, data);
            fail("Expected failure on a replay attack");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.INVALID_SECURITY);
        }

        replayCache.close();
    }

    @Test
    public void testReplayedTimestampNoExpires() throws Exception {

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecTimestamp timestamp = new WSSecTimestamp(secHeader);
        timestamp.setTimeToLive(0);
        Document createdDoc = timestamp.build();

        WSSecSignature builder = new WSSecSignature(secHeader);
        builder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        builder.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);

        WSEncryptionPart encP =
            new WSEncryptionPart(
                "Timestamp", WSConstants.WSU_NS, "");
        builder.getParts().add(encP);

        builder.prepare(crypto);

        List<javax.xml.crypto.dsig.Reference> referenceList =
            builder.addReferencesToSign(builder.getParts());

        builder.computeSignature(referenceList, false, null);

        if (LOG.isDebugEnabled()) {
            String outputString =
                XMLUtils.prettyDocumentToString(createdDoc);
            LOG.debug(outputString);
        }

        WSSConfig wssConfig = WSSConfig.getNewInstance();
        RequestData data = new RequestData();
        data.setWssConfig(wssConfig);
        data.setCallbackHandler(callbackHandler);
        data.setTimestampReplayCache(new MemoryReplayCache());

        // Successfully verify timestamp
        verify(createdDoc, wssConfig, data);

        // Now try again - a replay attack should be detected
        try {
            verify(createdDoc, wssConfig, data);
            fail("Expected failure on a replay attack");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.INVALID_SECURITY);
        }
    }

    @Test
    public void testEhCacheReplayedTimestampNoExpires() throws Exception {

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecTimestamp timestamp = new WSSecTimestamp(secHeader);
        timestamp.setTimeToLive(0);
        Document createdDoc = timestamp.build();

        WSSecSignature builder = new WSSecSignature(secHeader);
        builder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        builder.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);

        WSEncryptionPart encP =
            new WSEncryptionPart(
                "Timestamp", WSConstants.WSU_NS, "");
        builder.getParts().add(encP);

        builder.prepare(crypto);

        List<javax.xml.crypto.dsig.Reference> referenceList =
            builder.addReferencesToSign(builder.getParts());

        builder.computeSignature(referenceList, false, null);

        if (LOG.isDebugEnabled()) {
            String outputString =
                XMLUtils.prettyDocumentToString(createdDoc);
            LOG.debug(outputString);
        }

        WSSConfig wssConfig = WSSConfig.getNewInstance();
        RequestData data = new RequestData();
        data.setWssConfig(wssConfig);
        data.setCallbackHandler(callbackHandler);
        ReplayCache replayCache = createCache("wss4j.timestamp.cache-");
        data.setTimestampReplayCache(replayCache);

        // Successfully verify timestamp
        verify(createdDoc, wssConfig, data);

        // Now try again - a replay attack should be detected
        try {
            verify(createdDoc, wssConfig, data);
            fail("Expected failure on a replay attack");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.INVALID_SECURITY);
        }

        replayCache.close();
    }

    @Test
    public void testReplayedUsernameToken() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecUsernameToken builder = new WSSecUsernameToken(secHeader);
        builder.setUserInfo("wernerd", "verySecret");

        Document signedDoc = builder.build();

        if (LOG.isDebugEnabled()) {
            String outputString =
                XMLUtils.prettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }

        WSSConfig wssConfig = WSSConfig.getNewInstance();
        RequestData data = new RequestData();
        data.setCallbackHandler(new UsernamePasswordCallbackHandler());
        data.setWssConfig(wssConfig);
        data.setNonceReplayCache(new MemoryReplayCache());

        // Successfully verify UsernameToken
        verify(signedDoc, wssConfig, data);

        // Now try again - a replay attack should be detected
        try {
            verify(signedDoc, wssConfig, data);
            fail("Expected failure on a replay attack");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.INVALID_SECURITY);
        }
    }

    /**
     * The Nonce replay cache must be keyed on the decoded Nonce, not on the raw text of the Nonce
     * element. Base64 decoding ignores whitespace, so a replayed token whose Nonce has merely been
     * line-wrapped still authenticates - the password digest is computed over the decoded bytes -
     * and must still be detected as a replay.
     */
    @Test
    public void testReplayedUsernameTokenWithEquivalentNonceEncoding() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecUsernameToken builder = new WSSecUsernameToken(secHeader);
        builder.setUserInfo("wernerd", "verySecret");

        Document signedDoc = builder.build();

        String genuineMessage = XMLUtils.prettyDocumentToString(signedDoc);
        if (LOG.isDebugEnabled()) {
            LOG.debug(genuineMessage);
        }

        Matcher matcher = Pattern.compile("(<[^>]*Nonce[^>]*>)([^<]*)(</)").matcher(genuineMessage);
        assertTrue(matcher.find(), "No Nonce element was found");
        String nonce = matcher.group(2);

        // Wrap the Nonce across two lines. Base64 decoding ignores the newline, so this Nonce
        // decodes to exactly the same bytes and the password digest still verifies.
        String equivalentNonce = nonce.substring(0, 4) + "\n" + nonce.substring(4);
        assertNotEquals(nonce, equivalentNonce);
        assertArrayEquals(org.apache.xml.security.utils.XMLUtils.decode(nonce),
                          org.apache.xml.security.utils.XMLUtils.decode(equivalentNonce),
                          "The rewritten Nonce must decode to the same bytes");

        String replayedMessage = genuineMessage.substring(0, matcher.start(2))
            + equivalentNonce + genuineMessage.substring(matcher.end(2));

        WSSConfig wssConfig = WSSConfig.getNewInstance();
        RequestData data = new RequestData();
        data.setCallbackHandler(new UsernamePasswordCallbackHandler());
        data.setWssConfig(wssConfig);
        data.setNonceReplayCache(new MemoryReplayCache());

        // Successfully verify the genuine UsernameToken
        verify(SOAPUtil.toSOAPPart(genuineMessage), wssConfig, data);

        // The rewritten Nonce decodes to the same bytes, so this is a replay
        try {
            verify(SOAPUtil.toSOAPPart(replayedMessage), wssConfig, data);
            fail("Expected failure on a replay attack");
        } catch (WSSecurityException ex) {
            assertEquals(WSSecurityException.ErrorCode.INVALID_SECURITY, ex.getErrorCode());
        }
    }

    /**
     * An empty Nonce cannot be cached, so a UsernameToken carrying one must be rejected rather than
     * escape replay detection. The check happens before the token is validated, so the error names
     * the empty Nonce rather than reporting a replay. An element with no text and one containing only
     * whitespace must be treated alike.
     */
    @Test
    public void testUsernameTokenWithEmptyNonce() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecUsernameToken builder = new WSSecUsernameToken(secHeader);
        builder.setUserInfo("wernerd", "verySecret");

        String genuineMessage = XMLUtils.prettyDocumentToString(builder.build());

        Matcher matcher = Pattern.compile("(<[^>]*Nonce[^>]*>)([^<]*)(</)").matcher(genuineMessage);
        assertTrue(matcher.find(), "No Nonce element was found");

        for (String emptyNonce : new String[] {"", "   "}) {
            String message = genuineMessage.substring(0, matcher.start(2))
                + emptyNonce + genuineMessage.substring(matcher.end(2));

            WSSConfig wssConfig = WSSConfig.getNewInstance();
            RequestData data = new RequestData();
            data.setCallbackHandler(new UsernamePasswordCallbackHandler());
            data.setWssConfig(wssConfig);
            data.setNonceReplayCache(new MemoryReplayCache());

            try {
                verify(SOAPUtil.toSOAPPart(message), wssConfig, data);
                fail("Expected failure on an empty Nonce");
            } catch (WSSecurityException ex) {
                assertEquals(WSSecurityException.ErrorCode.INVALID_SECURITY, ex.getErrorCode());
                assertTrue(ex.getMessage().contains("The Nonce is empty"), ex.getMessage());
            }
        }
    }

    /**
     * A UsernameToken whose password fails to verify must not leave its Nonce in the replay cache.
     * Otherwise an attacker can replay a genuine token with a corrupted Password and send that
     * first: it is rejected, but it has claimed the genuine token's Nonce, so the genuine token is
     * then rejected as a replay when it arrives.
     */
    @Test
    public void testNonceCacheNotPoisonedByInvalidPassword() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecUsernameToken builder = new WSSecUsernameToken(secHeader);
        builder.setUserInfo("wernerd", "verySecret");

        Document signedDoc = builder.build();

        String genuineMessage = XMLUtils.prettyDocumentToString(signedDoc);
        if (LOG.isDebugEnabled()) {
            LOG.debug(genuineMessage);
        }

        // Corrupt the password digest, leaving the Nonce - the whole cache key - untouched
        Matcher matcher =
            Pattern.compile("(<[^>]*Password[^>]*>)([^<]*)(</)").matcher(genuineMessage);
        assertTrue(matcher.find(), "No Password element was found");
        String password = matcher.group(2);
        String corruptedPassword =
            (password.charAt(0) == 'A' ? "B" : "A") + password.substring(1);

        String tamperedMessage = genuineMessage.substring(0, matcher.start(2))
            + corruptedPassword + genuineMessage.substring(matcher.end(2));
        assertNotEquals(genuineMessage, tamperedMessage);

        WSSConfig wssConfig = WSSConfig.getNewInstance();
        RequestData data = new RequestData();
        data.setCallbackHandler(new UsernamePasswordCallbackHandler());
        data.setWssConfig(wssConfig);
        data.setNonceReplayCache(new MemoryReplayCache());

        // The tampered token must be rejected, as its password digest no longer verifies
        try {
            verify(SOAPUtil.toSOAPPart(tamperedMessage), wssConfig, data);
            fail("Expected failure on a tampered UsernameToken");
        } catch (WSSecurityException ex) {
            assertEquals(WSSecurityException.ErrorCode.FAILED_AUTHENTICATION, ex.getErrorCode());
        }

        // ...and it must not have cached the genuine token's Nonce on its way out
        verify(SOAPUtil.toSOAPPart(genuineMessage), wssConfig, data);

        // Replay detection must still work for the genuine token itself
        try {
            verify(SOAPUtil.toSOAPPart(genuineMessage), wssConfig, data);
            fail("Expected failure on a replay attack");
        } catch (WSSecurityException ex) {
            assertEquals(WSSecurityException.ErrorCode.INVALID_SECURITY, ex.getErrorCode());
        }
    }

    @Test
    public void testEhCacheReplayedUsernameToken() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecUsernameToken builder = new WSSecUsernameToken(secHeader);
        builder.setUserInfo("wernerd", "verySecret");

        Document signedDoc = builder.build();

        if (LOG.isDebugEnabled()) {
            String outputString =
                XMLUtils.prettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }

        WSSConfig wssConfig = WSSConfig.getNewInstance();
        RequestData data = new RequestData();
        data.setCallbackHandler(new UsernamePasswordCallbackHandler());
        data.setWssConfig(wssConfig);
        ReplayCache replayCache = createCache("wss4j.nonce.cache-");
        data.setNonceReplayCache(replayCache);

        // Successfully verify UsernameToken
        verify(signedDoc, wssConfig, data);

        // Now try again - a replay attack should be detected
        try {
            verify(signedDoc, wssConfig, data);
            fail("Expected failure on a replay attack");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.INVALID_SECURITY);
        }

        replayCache.close();
    }

    /**
     * A UsernameToken is accepted until its Created time plus the TTL, and the Created time may be
     * in the future (within the future TTL). The Nonce must be cached until then, not just until
     * the current time plus the TTL.
     */
    @Test
    public void testUsernameTokenFutureCreatedNonceExpiry() throws Exception {
        Instant created = Instant.now().plusSeconds(30L).truncatedTo(ChronoUnit.MILLIS);

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecUsernameToken builder = new WSSecUsernameToken(secHeader);
        builder.setUserInfo("wernerd", "verySecret");
        builder.setWsTimeSource(() -> created);

        Document signedDoc = builder.build();

        WSSConfig wssConfig = WSSConfig.getNewInstance();
        RequestData data = new RequestData();
        data.setCallbackHandler(new UsernamePasswordCallbackHandler());
        data.setWssConfig(wssConfig);
        RecordingReplayCache replayCache = new RecordingReplayCache();
        data.setNonceReplayCache(replayCache);

        verify(signedDoc, wssConfig, data);

        assertEquals(created.plusSeconds(data.getUtTTL()), replayCache.lastExpiry);
    }

    /**
     * A Timestamp with no Expires is accepted until its Created time plus the TTL, and the Created
     * time may be in the future (within the future TTL). The signature must be cached until then.
     */
    @Test
    public void testTimestampNoExpiresFutureCreatedReplayExpiry() throws Exception {
        Instant created = Instant.now().plusSeconds(30L).truncatedTo(ChronoUnit.MILLIS);

        RequestData data = new RequestData();
        RecordingReplayCache replayCache = verifySignedTimestamp(created, 0, data);

        assertEquals(created.plusSeconds(data.getTimeStampTTL()), replayCache.lastExpiry);
    }

    /**
     * If the Timestamp check is not strict, then Expires is not enforced, and a Timestamp is
     * accepted until its Created time plus the TTL, even if that is after its Expires time. The
     * signature must be cached until then.
     */
    @Test
    public void testNonStrictTimestampReplayExpiry() throws Exception {
        Instant created = Instant.now().truncatedTo(ChronoUnit.MILLIS);

        RequestData data = new RequestData();
        data.setTimeStampStrict(false);
        RecordingReplayCache replayCache = verifySignedTimestamp(created, 1, data);

        assertEquals(created.plusSeconds(data.getTimeStampTTL()), replayCache.lastExpiry);
    }

    /**
     * Sign a Timestamp with the given Created time and time to live, and verify it with the given
     * RequestData, returning the replay cache that the signature was cached in
     */
    private RecordingReplayCache verifySignedTimestamp(
        Instant created, int timeToLive, RequestData data
    ) throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecTimestamp timestamp = new WSSecTimestamp(secHeader);
        timestamp.setTimeToLive(timeToLive);
        timestamp.setWsTimeSource(() -> created);
        Document createdDoc = timestamp.build();

        WSSecSignature builder = new WSSecSignature(secHeader);
        builder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        builder.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);
        builder.getParts().add(new WSEncryptionPart("Timestamp", WSConstants.WSU_NS, ""));
        builder.prepare(crypto);
        List<javax.xml.crypto.dsig.Reference> referenceList =
            builder.addReferencesToSign(builder.getParts());
        builder.computeSignature(referenceList, false, null);

        WSSConfig wssConfig = WSSConfig.getNewInstance();
        data.setWssConfig(wssConfig);
        data.setCallbackHandler(callbackHandler);
        RecordingReplayCache replayCache = new RecordingReplayCache();
        data.setTimestampReplayCache(replayCache);

        verify(createdDoc, wssConfig, data);
        return replayCache;
    }

    /**
     * Test that creates, sends and processes an unsigned SAML 2 authentication assertion. This
     * is just a sanity test to make sure that it is possible to send the SAML token twice, as
     * no "OneTimeUse" Element is defined there is no problem with replaying it.
     * with a OneTimeUse Element
     */
    @Test
    public void testEhCacheReplayedSAML2() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
        callbackHandler.setIssuer("www.example.com");
        callbackHandler.setConfirmationMethod(SAML2Constants.CONF_BEARER);

        ConditionsBean conditions = new ConditionsBean();
        conditions.setTokenPeriodMinutes(5);

        callbackHandler.setConditions(conditions);

        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper samlAssertion = new SamlAssertionWrapper(samlCallback);

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecSAMLToken wsSign = new WSSecSAMLToken(secHeader);

        Document unsignedDoc = wsSign.build(samlAssertion);

        if (LOG.isDebugEnabled()) {
            String outputString = XMLUtils.prettyDocumentToString(unsignedDoc);
            LOG.debug(outputString);
        }

        WSSConfig wssConfig = WSSConfig.getNewInstance();
        SamlAssertionValidator assertionValidator = new SamlAssertionValidator();
        assertionValidator.setRequireBearerSignature(false);
        wssConfig.setValidator(WSConstants.SAML_TOKEN, assertionValidator);
        wssConfig.setValidator(WSConstants.SAML2_TOKEN, assertionValidator);

        RequestData data = new RequestData();
        data.setWssConfig(wssConfig);
        data.setCallbackHandler(callbackHandler);
        ReplayCache replayCache = createCache("wss4j.saml.one.time.use.cache-");
        data.setSamlOneTimeUseReplayCache(replayCache);

        // Successfully verify SAML Token
        verify(unsignedDoc, wssConfig, data);

        // Now try again - this should work fine as well
        verify(unsignedDoc, wssConfig, data);

        replayCache.close();
    }

    /**
     * Test that creates, sends and processes an unsigned SAML 2 authentication assertion
     * with a OneTimeUse Element
     */
    @Test
    public void testEhCacheReplayedSAML2OneTimeUse() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
        callbackHandler.setIssuer("www.example.com");
        callbackHandler.setConfirmationMethod(SAML2Constants.CONF_BEARER);

        ConditionsBean conditions = new ConditionsBean();
        conditions.setTokenPeriodMinutes(5);
        conditions.setOneTimeUse(true);

        callbackHandler.setConditions(conditions);

        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper samlAssertion = new SamlAssertionWrapper(samlCallback);

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecSAMLToken wsSign = new WSSecSAMLToken(secHeader);

        Document unsignedDoc = wsSign.build(samlAssertion);

        String outputString =
            XMLUtils.prettyDocumentToString(unsignedDoc);
        assertTrue(outputString.contains("OneTimeUse"));
        if (LOG.isDebugEnabled()) {
            LOG.debug(outputString);
        }

        WSSConfig wssConfig = WSSConfig.getNewInstance();
        SamlAssertionValidator assertionValidator = new SamlAssertionValidator();
        assertionValidator.setRequireBearerSignature(false);
        wssConfig.setValidator(WSConstants.SAML_TOKEN, assertionValidator);
        wssConfig.setValidator(WSConstants.SAML2_TOKEN, assertionValidator);

        RequestData data = new RequestData();
        data.setWssConfig(wssConfig);
        data.setCallbackHandler(callbackHandler);
        ReplayCache replayCache = createCache("wss4j.saml.one.time.use.cache-");
        data.setSamlOneTimeUseReplayCache(replayCache);

        // Successfully verify SAML Token
        verify(unsignedDoc, wssConfig, data);

        // Now try again - a replay attack should be detected
        try {
            verify(unsignedDoc, wssConfig, data);
            fail("Expected failure on a replay attack");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.INVALID_SECURITY);
        }

        replayCache.close();
    }

    /**
     * Test that a OneTimeUse assertion with no NotOnOrAfter is cached until IssueInstant + ttl,
     * which is how long checkIssueInstant accepts it for, rather than for the cache's default TTL.
     */
    @Test
    public void testSAML2OneTimeUseNoNotOnOrAfterCacheExpiry() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
        callbackHandler.setIssuer("www.example.com");
        callbackHandler.setConfirmationMethod(SAML2Constants.CONF_BEARER);

        ConditionsBean conditions = new ConditionsBean();
        conditions.setOneTimeUse(true);

        callbackHandler.setConditions(conditions);

        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper samlAssertion = new SamlAssertionWrapper(samlCallback);
        samlAssertion.getSaml2().getConditions().setNotOnOrAfter(null);
        Instant issueInstant = samlAssertion.getSaml2().getIssueInstant();
        assertNotNull(issueInstant);

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecSAMLToken wsSign = new WSSecSAMLToken(secHeader);

        Document unsignedDoc = wsSign.build(samlAssertion);

        String outputString =
            XMLUtils.prettyDocumentToString(unsignedDoc);
        assertTrue(outputString.contains("OneTimeUse"));
        assertTrue(!outputString.contains("NotOnOrAfter"));

        WSSConfig wssConfig = WSSConfig.getNewInstance();
        SamlAssertionValidator assertionValidator = new SamlAssertionValidator();
        assertionValidator.setRequireBearerSignature(false);
        wssConfig.setValidator(WSConstants.SAML_TOKEN, assertionValidator);
        wssConfig.setValidator(WSConstants.SAML2_TOKEN, assertionValidator);

        RequestData data = new RequestData();
        data.setWssConfig(wssConfig);
        data.setCallbackHandler(callbackHandler);
        RecordingReplayCache replayCache = new RecordingReplayCache();
        data.setSamlOneTimeUseReplayCache(replayCache);

        // Successfully verify SAML Token
        verify(unsignedDoc, wssConfig, data);

        // The IssueInstant is serialized with millisecond precision, so the validator sees it truncated
        assertEquals(issueInstant.truncatedTo(ChronoUnit.MILLIS).plusSeconds(assertionValidator.getTtl()),
                     replayCache.lastExpiry);

        // Now try again - a replay attack should be detected
        try {
            verify(unsignedDoc, wssConfig, data);
            fail("Expected failure on a replay attack");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.INVALID_SECURITY);
        }

        replayCache.close();
    }

    /**
     * A OneTimeUse assertion that is valid for longer than the replay cache can hold its identifier
     * could be replayed once the identifier has expired from the cache, so it must be rejected
     */
    @Test
    public void testSAML2OneTimeUseBeyondCacheTTL() throws Exception {
        // Valid for 2 hours, but a MemoryReplayCache only holds an identifier for 1 hour
        Document doc = createOneTimeUseAssertionDoc(2 * 60);

        SamlAssertionValidator assertionValidator = new SamlAssertionValidator();
        ReplayCache replayCache = new MemoryReplayCache();
        RequestData data = createOneTimeUseRequestData(assertionValidator, replayCache);

        try {
            verify(doc, data.getWssConfig(), data);
            fail("Expected failure as the assertion is valid for longer than the cache can hold it");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.INVALID_SECURITY);
        }

        replayCache.close();
    }

    /**
     * The check can be disabled, in which case the identifier is held for as long as the cache can
     */
    @Test
    public void testSAML2OneTimeUseBeyondCacheTTLAllowed() throws Exception {
        Document doc = createOneTimeUseAssertionDoc(2 * 60);

        SamlAssertionValidator assertionValidator = new SamlAssertionValidator();
        assertionValidator.setAllowOneTimeUseBeyondCacheTTL(true);
        ReplayCache replayCache = new MemoryReplayCache();
        RequestData data = createOneTimeUseRequestData(assertionValidator, replayCache);

        verify(doc, data.getWssConfig(), data);

        // Now try again - a replay attack should be detected
        try {
            verify(doc, data.getWssConfig(), data);
            fail("Expected failure on a replay attack");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.INVALID_SECURITY);
        }

        replayCache.close();
    }

    /**
     * A custom replay cache that does not say how long it holds an identifier for is not checked
     */
    @Test
    public void testSAML2OneTimeUseUnknownCacheTTL() throws Exception {
        Document doc = createOneTimeUseAssertionDoc(2 * 60);

        SamlAssertionValidator assertionValidator = new SamlAssertionValidator();
        RecordingReplayCache replayCache = new RecordingReplayCache();
        RequestData data = createOneTimeUseRequestData(assertionValidator, replayCache);

        verify(doc, data.getWssConfig(), data);
        assertNotNull(replayCache.lastExpiry);

        replayCache.close();
    }

    private Document createOneTimeUseAssertionDoc(int tokenPeriodMinutes) throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
        callbackHandler.setIssuer("www.example.com");
        callbackHandler.setConfirmationMethod(SAML2Constants.CONF_BEARER);

        ConditionsBean conditions = new ConditionsBean();
        conditions.setTokenPeriodMinutes(tokenPeriodMinutes);
        conditions.setOneTimeUse(true);
        callbackHandler.setConditions(conditions);

        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper samlAssertion = new SamlAssertionWrapper(samlCallback);

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecSAMLToken wsSign = new WSSecSAMLToken(secHeader);
        return wsSign.build(samlAssertion);
    }

    private RequestData createOneTimeUseRequestData(
        SamlAssertionValidator assertionValidator, ReplayCache replayCache
    ) {
        WSSConfig wssConfig = WSSConfig.getNewInstance();
        assertionValidator.setRequireBearerSignature(false);
        wssConfig.setValidator(WSConstants.SAML_TOKEN, assertionValidator);
        wssConfig.setValidator(WSConstants.SAML2_TOKEN, assertionValidator);

        RequestData data = new RequestData();
        data.setWssConfig(wssConfig);
        data.setCallbackHandler(callbackHandler);
        data.setSamlOneTimeUseReplayCache(replayCache);
        return data;
    }

    /**
     * Verifies the soap envelope
     *
     * @param doc soap document
     * @param wssConfig
     * @throws Exception Thrown when there is a problem in verification
     */
    private WSHandlerResult verify(
        Document doc, WSSConfig wssConfig, RequestData data
    ) throws Exception {
        WSSecurityEngine secEngine = new WSSecurityEngine();
        secEngine.setWssConfig(wssConfig);
        Element elem = WSSecurityUtil.getSecurityHeader(doc, null);
        data.setSigVerCrypto(crypto);
        return secEngine.processSecurityHeader(elem, data);
    }

    /**
     * A ReplayCache that records the expiry it was last asked to cache an identifier for
     */
    private static final class RecordingReplayCache implements ReplayCache {
        private final MemoryReplayCache delegate = new MemoryReplayCache();
        private Instant lastExpiry;

        @Override
        public void add(String identifier) {
            lastExpiry = null;
            delegate.add(identifier);
        }

        @Override
        public void add(String identifier, Instant expiry) {
            lastExpiry = expiry;
            delegate.add(identifier, expiry);
        }

        @Override
        public boolean contains(String identifier) {
            return delegate.contains(identifier);
        }

        @Override
        public void close() throws IOException {
            delegate.close();
        }
    }
}
