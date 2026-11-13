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
package org.apache.wss4j.stax.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import javax.crypto.Cipher;
import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.XMLStreamWriter;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.wss4j.common.ext.Attachment;
import org.apache.wss4j.common.util.AttachmentUtils;
import org.apache.wss4j.common.util.SOAPUtil;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.ext.WSSSecurityProperties;
import org.apache.wss4j.stax.setup.InboundWSSec;
import org.apache.wss4j.stax.setup.OutboundWSSec;
import org.apache.wss4j.stax.setup.WSSec;
import org.apache.wss4j.stax.test.utils.StAX2DOM;
import org.apache.wss4j.stax.test.utils.XmlReaderToWriter;
import org.apache.xml.security.stax.ext.SecurePart;
import org.apache.xml.security.stax.securityEvent.SecurityEvent;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * An encrypted attachment is decrypted by WSS4J itself, not by Santuario, so the key recovered from
 * the EncryptedKey must be prepared there too. A key decryption that fails yields a random key of the
 * length the content encryption algorithm requires; a key decryption that succeeds, but yields a key
 * of some other length, must fail in the same way. Otherwise the outcome tells the sender whether the
 * RSA key transport decryption produced a well-formed plaintext. This is the streaming counterpart of
 * the DOM EncryptedKeyLengthOracleTest.
 */
public class EncryptedKeyLengthOracleTest extends AbstractTestBase {

    private static final String RSA_OAEP_MGF1P = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p";

    private static final SecureRandom RANDOM = new SecureRandom();

    public EncryptedKeyLengthOracleTest() throws Exception {
    }

    @Test
    public void testAttachmentContentOnly() throws Exception {
        checkNoOracle(SecurePart.Modifier.Content, false);
    }

    @Test
    public void testAttachmentComplete() throws Exception {
        checkNoOracle(SecurePart.Modifier.Element, false);
    }

    /**
     * The EncryptedData of the attachment names the EncryptedKey through a SecurityTokenReference in
     * its KeyInfo, rather than the EncryptedKey naming it in a ReferenceList.
     */
    @Test
    public void testAttachmentContentOnlyThroughSecurityTokenReference() throws Exception {
        checkNoOracle(SecurePart.Modifier.Content, true);
    }

    private void checkNoOracle(SecurePart.Modifier modifier, boolean keyInfoReference) throws Exception {
        EncryptedMessage message = encryptAttachment(modifier);

        // The untampered message decrypts, so a failure below is down to the key
        assertEquals("OK", decrypt(message, null, keyInfoReference));

        // The key decryption fails
        byte[] random = new byte[256];
        RANDOM.nextBytes(random);
        String unwrapFails = decrypt(message, random, keyInfoReference);

        // The key decryption succeeds, but the key has the wrong length for aes128-gcm
        String tooShort = decrypt(message, wrapKey(new byte[7]), keyInfoReference);
        String tooLong = decrypt(message, wrapKey(new byte[40]), keyInfoReference);
        // A length the cipher would take, but not the one aes128-gcm requires
        String aes256Length = decrypt(message, wrapKey(new byte[32]), keyInfoReference);
        // The key decryption succeeds with the right length, but the key is wrong
        String wrongKey = decrypt(message, wrapKey(new byte[16]), keyInfoReference);

        assertEquals(wrongKey, unwrapFails);
        assertEquals(unwrapFails, tooShort);
        assertEquals(unwrapFails, tooLong);
        assertEquals(unwrapFails, aes256Length);
    }

    private static final class EncryptedMessage {
        private byte[] soap;
        private String attachmentId;
        private byte[] attachmentBytes;
        private Map<String, String> attachmentHeaders;
        private String attachmentMimeType;
    }

    private EncryptedMessage encryptAttachment(SecurePart.Modifier modifier) throws Exception {
        final String attachmentId = UUID.randomUUID().toString();
        final Attachment attachment = new Attachment();
        attachment.setMimeType("text/xml");
        Map<String, String> headers = new HashMap<>();
        headers.put(AttachmentUtils.MIME_HEADER_CONTENT_ID, "<attachment=" + attachmentId + ">");
        headers.put(AttachmentUtils.MIME_HEADER_CONTENT_TYPE, "text/xml; charset=UTF-8");
        attachment.addHeaders(headers);
        attachment.setId(attachmentId);
        attachment.setSourceStream(new ByteArrayInputStream(SOAPUtil.SAMPLE_SOAP_MSG.getBytes(StandardCharsets.UTF_8)));
        AttachmentCallbackHandler attachmentCallbackHandler =
            new AttachmentCallbackHandler(Collections.singletonList(attachment));

        WSSSecurityProperties securityProperties = new WSSSecurityProperties();
        List<WSSConstants.Action> actions = new ArrayList<>();
        actions.add(WSSConstants.ENCRYPTION);
        securityProperties.setActions(actions);
        securityProperties.loadEncryptionKeystore(
            this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
        securityProperties.setEncryptionUser("receiver");
        // Only the attachment, so that the SOAP Body does not fail first
        securityProperties.addEncryptionPart(new SecurePart("cid:Attachments", modifier));
        securityProperties.setAttachmentCallbackHandler(attachmentCallbackHandler);
        securityProperties.setEncryptionSymAlgorithm(WSSConstants.NS_XENC11_AES128_GCM);
        securityProperties.setEncryptionKeyTransportAlgorithm(RSA_OAEP_MGF1P);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
        XMLStreamWriter xmlStreamWriter =
            wsSecOut.processOutMessage(baos, StandardCharsets.UTF_8.name(), new ArrayList<SecurityEvent>());
        XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(
            this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
        XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
        xmlStreamWriter.close();

        Attachment encryptedAttachment = attachmentCallbackHandler.getResponseAttachments().get(0);
        EncryptedMessage message = new EncryptedMessage();
        message.soap = baos.toByteArray();
        message.attachmentId = encryptedAttachment.getId();
        message.attachmentBytes = readAll(encryptedAttachment.getSourceStream());
        message.attachmentHeaders = encryptedAttachment.getHeaders();
        message.attachmentMimeType = encryptedAttachment.getMimeType();
        return message;
    }

    /**
     * RSA-OAEP encrypt the given bytes under the recipient's public key, as an attacker can do.
     */
    private byte[] wrapKey(byte[] keyBytes) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("JKS");
        try (InputStream inputStream =
                 this.getClass().getClassLoader().getResourceAsStream("transmitter.jks")) {
            keyStore.load(inputStream, "default".toCharArray());
        }
        PublicKey publicKey = ((X509Certificate) keyStore.getCertificate("receiver")).getPublicKey();
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        RANDOM.nextBytes(keyBytes);
        return cipher.doFinal(keyBytes);
    }

    /**
     * Process the message, with the EncryptedKey's CipherValue replaced by the given bytes if not null,
     * read the decrypted attachment, and describe how it failed.
     */
    private String decrypt(EncryptedMessage message, byte[] encryptedKeyBytes, boolean keyInfoReference)
        throws Exception {
        byte[] soap = tamper(message.soap, encryptedKeyBytes, keyInfoReference);

        Attachment attachment = new Attachment();
        attachment.setId(message.attachmentId);
        attachment.setMimeType(message.attachmentMimeType);
        attachment.addHeaders(message.attachmentHeaders);
        attachment.setSourceStream(new ByteArrayInputStream(message.attachmentBytes));
        AttachmentCallbackHandler attachmentCallbackHandler =
            new AttachmentCallbackHandler(Collections.singletonList(attachment));

        WSSSecurityProperties securityProperties = new WSSSecurityProperties();
        securityProperties.loadDecryptionKeystore(
            this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
        securityProperties.setCallbackHandler(new CallbackHandlerImpl());
        securityProperties.setAttachmentCallbackHandler(attachmentCallbackHandler);

        try {
            // Do not mask errors, so that any difference shows
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties, false, true);
            XMLStreamReader xmlStreamReader =
                wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(soap)));
            StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            Attachment responseAttachment = attachmentCallbackHandler.getResponseAttachments().get(0);
            readAll(responseAttachment.getSourceStream());
            return "OK";
        } catch (Exception e) {
            return describe(e);
        }
    }

    private byte[] tamper(byte[] soap, byte[] encryptedKeyBytes, boolean keyInfoReference) throws Exception {
        if (encryptedKeyBytes == null && !keyInfoReference) {
            return soap;
        }
        Document doc = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(soap));

        Element encryptedKey =
            (Element) doc.getElementsByTagNameNS(WSConstants.ENC_NS, "EncryptedKey").item(0);
        assertNotNull(encryptedKey);
        Element encryptionMethod =
            (Element) encryptedKey.getElementsByTagNameNS(WSConstants.ENC_NS, "EncryptionMethod").item(0);
        assertEquals(RSA_OAEP_MGF1P, encryptionMethod.getAttributeNS(null, "Algorithm"));

        if (encryptedKeyBytes != null) {
            Element cipherValue =
                (Element) encryptedKey.getElementsByTagNameNS(WSConstants.ENC_NS, "CipherValue").item(0);
            cipherValue.setTextContent(Base64.getEncoder().encodeToString(encryptedKeyBytes));
        }

        if (keyInfoReference) {
            // Drop the ReferenceList, and have the attachment's EncryptedData name the EncryptedKey
            Element referenceList =
                (Element) encryptedKey.getElementsByTagNameNS(WSConstants.ENC_NS, "ReferenceList").item(0);
            encryptedKey.removeChild(referenceList);

            NodeList encryptedDatas = doc.getElementsByTagNameNS(WSConstants.ENC_NS, "EncryptedData");
            assertEquals(1, encryptedDatas.getLength());
            Element encryptedData = (Element) encryptedDatas.item(0);
            Element dataEncryptionMethod =
                (Element) encryptedData.getElementsByTagNameNS(WSConstants.ENC_NS, "EncryptionMethod").item(0);

            // The outbound engine may already have written a KeyInfo there; xenc allows only one,
            // so replace it with a SecurityTokenReference to the EncryptedKey
            for (Node child = encryptedData.getFirstChild(); child != null; child = child.getNextSibling()) {
                if (WSConstants.SIG_NS.equals(child.getNamespaceURI()) && "KeyInfo".equals(child.getLocalName())) {
                    encryptedData.removeChild(child);
                    break;
                }
            }

            Element keyInfo = doc.createElementNS(WSConstants.SIG_NS, "ds:KeyInfo");
            Element str = doc.createElementNS(WSConstants.WSSE_NS, "wsse:SecurityTokenReference");
            Element reference = doc.createElementNS(WSConstants.WSSE_NS, "wsse:Reference");
            reference.setAttributeNS(null, "URI", "#" + encryptedKey.getAttributeNS(null, "Id"));
            reference.setAttributeNS(null, "ValueType", WSConstants.WSS_ENC_KEY_VALUE_TYPE);
            str.appendChild(reference);
            keyInfo.appendChild(str);
            encryptedData.insertBefore(keyInfo, dataEncryptionMethod.getNextSibling());
        }

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        TRANSFORMER_FACTORY.newTransformer().transform(new DOMSource(doc), new StreamResult(baos));
        return baos.toByteArray();
    }

    /**
     * The exception types and messages down the cause chain. Messages are kept, as an application
     * reading the attachment may show them.
     */
    private static String describe(Throwable t) {
        StringBuilder sb = new StringBuilder();
        for (Throwable c = t; c != null; c = c.getCause()) {
            sb.append(c.getClass().getName()).append(": ").append(c.getMessage()).append('\n');
        }
        return sb.toString();
    }

    private static byte[] readAll(InputStream inputStream) throws Exception {
        try (InputStream in = inputStream) {
            return in.readAllBytes();
        }
    }
}
