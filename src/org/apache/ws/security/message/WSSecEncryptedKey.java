/*
 * Copyright  2003-2004 The Apache Software Foundation.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package org.apache.ws.security.message;

import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.message.token.BinarySecurity;
import org.apache.ws.security.message.token.Reference;
import org.apache.ws.security.message.token.SecurityTokenReference;
import org.apache.ws.security.message.token.X509Security;
import org.apache.ws.security.util.WSSecurityUtil;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.keys.content.X509Data;
import org.apache.xml.security.keys.content.x509.XMLX509IssuerSerial;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Text;

/**
 * Builder class to build an EncryptedKey.
 * 
 * This is expecially useful in the case where the same
 * <code>EncryptedKey</code> has to be used to sign and encrypt the message In
 * such a situation this builder will add the <code>EncryptedKey</code> to the
 * security header and we can use the information form the builder to provide to
 * other builders to reference to the token
 */
public class WSSecEncryptedKey extends WSSecBase {

    private static Log log = LogFactory.getLog(WSSecEncryptedKey.class
            .getName());
    
    protected boolean doDebug = false;
    
    protected Document document;
    /**
     * soap:Envelope element
     */
    protected Element envelope = null;
    /**
     * Session key used as the secret in key derivation
     */
    protected byte[] ephemeralKey;

    /**
     * Remote user's alias to obtain the cert to encrypt the ephemeral key
     */
    protected String encrUser = null;

    /**
     * Algorithm used to encrypt the ephemeral key
     */
    protected String keyEncAlgo = WSConstants.KEYTRANSPORT_RSA15;
    
    /**
     * xenc:EncryptedKey element
     */
    protected Element encryptedKeyElement = null;

    /**
     * The Token identifier of the token that the <code>DerivedKeyToken</code> 
     * is (or to be) derived from.
     */
    protected String tokneIdentifier = null;

    /**
     * BinarySecurityToken to be included in the case where BST_DIRECT_REFERENCE
     * is used to refer to the asymm encryption cert
     */
    protected BinarySecurity bstToken = null;

    
    /**
     * This will actually prepend the <code>EncryptedKey</code> to the 
     * security header
     * @param doc
     * @param crypto
     * @param secHeader
     * @throws WSSecurityException
     */
    public void commit(Document doc, Crypto crypto, WSSecHeader secHeader)
            throws WSSecurityException {
        prependToHeader(secHeader);
        prependBSTElementToHeader(secHeader);
    }
    
    public void build(Document doc, Crypto crypto, WSSecHeader secHeader)
            throws WSSecurityException {
        prepare(doc, crypto);
    }
    
    /**
     * Prepare the ephemeralKey and the tokens required to be added to the 
     * security header
     * @param doc
     * @param crypto
     * @throws WSSecurityException
     */
    protected void prepare(Document doc, Crypto crypto)
            throws WSSecurityException {

        document = doc;

        /*
         * Set up the ephemeral key
         */
        if (this.ephemeralKey == null) {
            this.ephemeralKey = generateEphemeralKey();
        }

        /*
         * Get the certificate that contains the public key for the public key
         * algorithm that will encrypt the generated symmetric (session) key.
         */
        X509Certificate remoteCert = null;

        X509Certificate[] certs = crypto.getCertificates(encrUser);
        if (certs == null || certs.length <= 0) {
            throw new WSSecurityException(WSSecurityException.FAILURE,
                    "invalidX509Data", new Object[] { "for Encryption" });
        }
        remoteCert = certs[0];

        String certUri = "EncCertId-" + remoteCert.hashCode();
        Cipher cipher = WSSecurityUtil.getCipherInstance(keyEncAlgo);
        try {
            cipher.init(Cipher.ENCRYPT_MODE, remoteCert);
        } catch (InvalidKeyException e) {
            throw new WSSecurityException(WSSecurityException.FAILED_ENC_DEC,
                    null, null, e);
        }

        if (doDebug) {
            log.debug("cipher blksize: " + cipher.getBlockSize()
                    + ", symm key length: " + this.ephemeralKey.length);
        }
        if (cipher.getBlockSize() < this.ephemeralKey.length) {
            throw new WSSecurityException(
                    WSSecurityException.FAILURE,
                    "unsupportedKeyTransp",
                    new Object[] { "public key algorithm too weak to encrypt " +
                            "symmetric key" });
        }
        byte[] encryptedKey = null;
        try {
            encryptedKey = cipher.doFinal(this.ephemeralKey);
        } catch (IllegalStateException e1) {
            throw new WSSecurityException(WSSecurityException.FAILED_ENC_DEC,
                    null, null, e1);
        } catch (IllegalBlockSizeException e1) {
            throw new WSSecurityException(WSSecurityException.FAILED_ENC_DEC,
                    null, null, e1);
        } catch (BadPaddingException e1) {
            throw new WSSecurityException(WSSecurityException.FAILED_ENC_DEC,
                    null, null, e1);
        }
        Text keyText = WSSecurityUtil.createBase64EncodedTextNode(doc,
                encryptedKey);

        /*
         * Now we need to setup the EncryptedKey header block 1) create a
         * EncryptedKey element and set a wsu:Id for it 2) Generate ds:KeyInfo
         * element, this wraps the wsse:SecurityTokenReference 3) Create and set
         * up the SecurityTokenReference according to the keyIdentifer parameter
         * 4) Create the CipherValue element structure and insert the encrypted
         * session key
         */
        encryptedKeyElement = createEnrcyptedKey(doc, keyEncAlgo);
        this.tokneIdentifier = "EncKeyId-" + encryptedKeyElement.hashCode();
            encryptedKeyElement.setAttributeNS(null, "Id", this.tokneIdentifier);

        KeyInfo keyInfo = new KeyInfo(doc);

        SecurityTokenReference secToken = new SecurityTokenReference(doc);

        switch (keyIdentifierType) {
        case WSConstants.X509_KEY_IDENTIFIER:
            secToken.setKeyIdentifier(remoteCert);
            break;

        case WSConstants.SKI_KEY_IDENTIFIER:
            secToken.setKeyIdentifierSKI(remoteCert, crypto);
            break;

        case WSConstants.THUMBPRINT_IDENTIFIER:
            secToken.setKeyIdentifierThumb(remoteCert);
            break;

        case WSConstants.ISSUER_SERIAL:
            XMLX509IssuerSerial data = new XMLX509IssuerSerial(doc, remoteCert);
            X509Data x509Data = new X509Data(doc);
            x509Data.add(data);
            secToken.setX509IssuerSerial(x509Data);
            break;

        case WSConstants.BST_DIRECT_REFERENCE:
            Reference ref = new Reference(doc);
            ref.setURI("#" + certUri);
            bstToken = new X509Security(doc);
            ((X509Security) bstToken).setX509Certificate(remoteCert);
            bstToken.setID(certUri);
            ref.setValueType(bstToken.getValueType());
            secToken.setReference(ref);
            break;

        default:
            throw new WSSecurityException(WSSecurityException.FAILURE,
                    "unsupportedKeyId");
        }

        keyInfo.addUnknownElement(secToken.getElement());
        WSSecurityUtil.appendChildElement(doc, encryptedKeyElement, keyInfo
                .getElement());

        Element xencCipherValue = createCipherValue(doc, encryptedKeyElement);
        xencCipherValue.appendChild(keyText);

        envelope = doc.getDocumentElement();
        envelope.setAttributeNS(WSConstants.XMLNS_NS, "xmlns:"
                + WSConstants.ENC_PREFIX, WSConstants.ENC_NS);

            
    }
    
    /**
     * Create an ephemeral key
     * @return
     * @throws WSSecurityException
     */
    protected byte[] generateEphemeralKey() throws WSSecurityException {
        try {
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
            byte[] temp = new byte[16];
            random.nextBytes(temp);
            return temp;
        } catch (Exception e) {
            throw new WSSecurityException(
                    "Error in creating the ephemeral key", e);
        }
    }
    
    /**
     * Sets the alias of the remote cert which is usef to encrypt the ephemeral 
     * key
     * @param user
     */
    public void setEncryptionUser(String user) {
        this.encrUser = user;
    }
    
    
    protected Element createEnrcyptedKey(Document doc,
            String keyTransportAlgo) {
        Element encryptedKey = doc.createElementNS(WSConstants.ENC_NS,
                WSConstants.ENC_PREFIX + ":EncryptedKey");

        WSSecurityUtil.setNamespace(encryptedKey, WSConstants.ENC_NS,
                WSConstants.ENC_PREFIX);
        Element encryptionMethod = doc.createElementNS(WSConstants.ENC_NS,
                WSConstants.ENC_PREFIX + ":EncryptionMethod");
        encryptionMethod.setAttributeNS(null, "Algorithm", keyTransportAlgo);
        WSSecurityUtil.appendChildElement(doc, encryptedKey, encryptionMethod);
        return encryptedKey;
    }
    
    protected Element createCipherValue(Document doc, Element encryptedKey) {
        Element cipherData = doc.createElementNS(WSConstants.ENC_NS,
                WSConstants.ENC_PREFIX + ":CipherData");
        Element cipherValue = doc.createElementNS(WSConstants.ENC_NS,
                WSConstants.ENC_PREFIX + ":CipherValue");
        cipherData.appendChild(cipherValue);
        WSSecurityUtil.appendChildElement(doc, encryptedKey, cipherData);
        return cipherValue;
    }
    
    /**
     * Prepend the EncryptedKey element to the elements already in the Security
     * header.
     * 
     * The method can be called any time after <code>prepare()</code>. This
     * allows to insert the EncryptedKey element at any position in the Security
     * header.
     * 
     * @param secHeader
     *            The security header that holds the Signature element.
     */
    protected void prependToHeader(WSSecHeader secHeader) {
        WSSecurityUtil.prependChildElement(document, secHeader
                .getSecurityHeader(), encryptedKeyElement, false);
    }
    
    /**
     * Prepend the BinarySecurityToken to the elements already in the Security
     * header.
     * 
     * The method can be called any time after <code>prepare()</code>. This
     * allows to insert the BST element at any position in the Security header.
     * 
     * @param secHeader
     *            The security header that holds the BST element.
     */
    protected void prependBSTElementToHeader(WSSecHeader secHeader) {
        if (bstToken != null) {
            WSSecurityUtil.prependChildElement(document, secHeader
                    .getSecurityHeader(), bstToken.getElement(), false);
        }
        bstToken = null;
    }


    /**
     * @return Returns the ephemeralKey.
     */
    public byte[] getEphemeralKey() {
        return ephemeralKey;
    }

    /**
     * @return Returns the tokneIdentifier.
     */
    public String getTokneIdentifier() {
        return tokneIdentifier;
    }
    
}
