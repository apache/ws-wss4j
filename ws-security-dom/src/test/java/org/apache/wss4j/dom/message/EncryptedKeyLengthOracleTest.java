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

import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.security.auth.callback.CallbackHandler;

import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.crypto.CryptoType;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.util.KeyUtils;
import org.apache.wss4j.common.util.SOAPUtil;
import org.apache.wss4j.common.util.XMLUtils;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.common.KeystoreCallbackHandler;
import org.apache.wss4j.dom.engine.WSSConfig;
import org.apache.wss4j.dom.engine.WSSecurityEngine;
import org.apache.wss4j.dom.handler.RequestData;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assumptions.assumeFalse;

/**
 * The receiver must not reveal whether the private key operation on an EncryptedKey produced a
 * well formed PKCS#1 v1.5 plaintext. A decryption that fails is answered with a random key of
 * exactly the length the EncryptedData algorithm requires, so that the failure surfaces as the
 * data not decrypting. A decryption that succeeds but yields a plaintext of some other length
 * must fail in the same way and not in one of its own - the attacker chooses the EncryptedData
 * algorithm, and so chooses the length that counts as "other", which makes any distinction
 * between the two a Bleichenbacher oracle on the key transport.
 * <p/>
 * The EncryptedData is GCM rather than CBC so that the comparison is not a lottery. Decrypting
 * with a key that is merely wrong fails on the authentication tag every time, whereas the
 * ISO10126 padding CBC uses is accepted by chance for about one random key in eighteen, and the
 * garbage that comes out then fails in the XML parser instead - a difference that says nothing
 * about the property under test.
 */
public class EncryptedKeyLengthOracleTest {

    /** The block type PKCS#1 v1.5 uses for encryption. */
    private static final byte BLOCK_TYPE = 0x02;

    /** Any other block type makes the unpadding reject the plaintext. */
    private static final byte NON_CONFORMING_BLOCK_TYPE = 0x03;

    private final Crypto crypto;
    private final CallbackHandler callbackHandler = new KeystoreCallbackHandler();
    private final boolean isIBMJdK = System.getProperty("java.vendor").contains("IBM");

    public EncryptedKeyLengthOracleTest() throws Exception {
        WSSConfig.init();
        crypto = CryptoFactory.getInstance("wss40.properties");
    }

    @Test
    public void testWrongLengthPlaintextIsIndistinguishableFromFailedDecryption() throws Exception {
        assumeFalse(isIBMJdK);

        // A ciphertext that does not decrypt to a well formed plaintext at all: the block type
        // is 0x03 where PKCS#1 v1.5 encryption requires 0x02, so the unpadding rejects it.
        WSSecurityException failedDecryption =
            decryptWithCipherValue(forgeCiphertext(NON_CONFORMING_BLOCK_TYPE, 16));

        // A ciphertext that decrypts to a perfectly well formed PKCS#1 v1.5 plaintext, whose
        // payload is simply not 16 bytes long - the length aes128-gcm requires. Only an attacker
        // probing the key transport ever produces one of these.
        WSSecurityException wrongLength = decryptWithCipherValue(forgeCiphertext(BLOCK_TYPE, 24));

        assertEquals(failedDecryption.getErrorCode(), wrongLength.getErrorCode(),
            "A well formed plaintext of the wrong length must not be distinguishable from a "
            + "plaintext that is not well formed");
        assertEquals(failedDecryption.getMessage(), wrongLength.getMessage(),
            "A well formed plaintext of the wrong length must not be distinguishable from a "
            + "plaintext that is not well formed");
    }

    /**
     * The same, for a plaintext longer than the maximum key size rather than merely the wrong
     * length: that is rejected by a different branch of KeyUtils.prepareSecretKey.
     */
    @Test
    public void testOverlongPlaintextIsIndistinguishableFromFailedDecryption() throws Exception {
        assumeFalse(isIBMJdK);

        WSSecurityException failedDecryption =
            decryptWithCipherValue(forgeCiphertext(NON_CONFORMING_BLOCK_TYPE, 16));

        WSSecurityException overlong = decryptWithCipherValue(forgeCiphertext(BLOCK_TYPE, 200));

        assertEquals(failedDecryption.getErrorCode(), overlong.getErrorCode());
        assertEquals(failedDecryption.getMessage(), overlong.getMessage());
    }

    /**
     * Build an rsa-1_5 / aes128-gcm encrypted message, substitute the given bytes for the
     * CipherValue of its EncryptedKey, and process it. The message never decrypts - the point is
     * only how it fails.
     */
    private WSSecurityException decryptWithCipherValue(byte[] cipherValue) throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecEncrypt builder = new WSSecEncrypt(secHeader);
        builder.setUserInfo("wss40");
        builder.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
        builder.setSymmetricEncAlgorithm(WSConstants.AES_128_GCM);
        builder.setKeyEncAlgo(WSConstants.KEYTRANSPORT_RSA15);

        KeyGenerator keyGen = KeyUtils.getKeyGenerator(WSConstants.AES_128_GCM);
        SecretKey symmetricKey = keyGen.generateKey();
        Document encryptedDoc = builder.build(crypto, symmetricKey);

        Element encryptedKey =
            XMLUtils.findElement(encryptedDoc.getDocumentElement(), "EncryptedKey", WSConstants.ENC_NS);
        assertNotNull(encryptedKey);
        Element cipherValueElement =
            XMLUtils.findElement(encryptedKey, "CipherValue", WSConstants.ENC_NS);
        assertNotNull(cipherValueElement);
        cipherValueElement.setTextContent(
            org.apache.xml.security.utils.XMLUtils.encodeToString(cipherValue));

        RequestData data = new RequestData();
        data.setDecCrypto(crypto);
        data.setSigVerCrypto(crypto);
        data.setCallbackHandler(callbackHandler);
        data.setAllowRSA15KeyTransportAlgorithm(true);

        WSSecurityEngine secEngine = new WSSecurityEngine();
        return assertThrows(WSSecurityException.class,
            () -> secEngine.processSecurityHeader(encryptedDoc, data));
    }

    /**
     * Raw-RSA encrypt EM = 0x00 || blockType || PS || 0x00 || M under the recipient's public key.
     * With the PKCS#1 v1.5 block type the receiver's unpadding succeeds and hands back a payload
     * of exactly payloadLength bytes, which is what a Bleichenbacher probe looks like once it
     * finds a conforming ciphertext; with any other block type the unpadding rejects it.
     */
    private byte[] forgeCiphertext(byte blockType, int payloadLength) throws Exception {
        int k = keySizeInBytes();
        byte[] em = new byte[k];
        em[0] = 0x00;
        em[1] = blockType;
        int paddingLength = k - 3 - payloadLength;
        SecureRandom random = new SecureRandom();
        for (int i = 0; i < paddingLength; i++) {
            byte b;
            do {
                b = (byte)random.nextInt(256);
            } while (b == 0);
            em[2 + i] = b;
        }
        em[2 + paddingLength] = 0x00;
        for (int i = 0; i < payloadLength; i++) {
            em[3 + paddingLength + i] = (byte)(i + 1);
        }

        Cipher rsa = Cipher.getInstance("RSA/ECB/NoPadding");
        rsa.init(Cipher.ENCRYPT_MODE, recipientPublicKey());
        return rsa.doFinal(em);
    }

    private PublicKey recipientPublicKey() throws Exception {
        CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
        cryptoType.setAlias("wss40");
        X509Certificate[] certs = crypto.getX509Certificates(cryptoType);
        assertNotNull(certs);
        return certs[0].getPublicKey();
    }

    private int keySizeInBytes() throws Exception {
        return (((RSAPublicKey)recipientPublicKey()).getModulus().bitLength() + 7) / 8;
    }
}
