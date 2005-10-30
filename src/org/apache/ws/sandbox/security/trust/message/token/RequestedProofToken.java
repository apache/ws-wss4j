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
package org.apache.ws.sandbox.security.trust.message.token;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.sandbox.security.trust.TrustConstants;
import org.apache.ws.security.SOAPConstants;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.message.WSEncryptBody;
import org.apache.ws.security.message.token.BinarySecurity;
import org.apache.ws.security.message.token.Reference;
import org.apache.ws.security.message.token.SecurityTokenReference;
import org.apache.ws.security.message.token.X509Security;
import org.apache.ws.security.processor.EncryptedKeyProcessor;
import org.apache.ws.security.util.DOM2Writer;
import org.apache.ws.security.util.Loader;
import org.apache.ws.security.util.WSSecurityUtil;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.encryption.XMLEncryptionException;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.keys.content.X509Data;
import org.apache.xml.security.keys.content.x509.XMLX509IssuerSerial;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.w3c.dom.Text;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.security.auth.callback.CallbackHandler;
import javax.xml.namespace.QName;

/**
 * @author Dimuthu Leelarathne. (muthulee@yahoo.com)
 * @author Ruchith Fernando
 */
public class RequestedProofToken {
    private static Log log =
            LogFactory.getLog(RequestedProofToken.class.getName());

    public static final QName TOKEN =
            new QName(TrustConstants.WST_NS, "RequestedProofToken");

    private Element element;
    private byte[] sharedSecret;

    /**
     * Constructor.
     *
     * @param doc    is the SOAP envelop.
     * @throws WSSecurityException
     */
    public RequestedProofToken(Document doc) throws WSSecurityException {
        this.element = doc.createElementNS(TrustConstants.WST_NS, TrustConstants.WST_PREFIX + ":" + TOKEN.getLocalPart());
        WSSecurityUtil.setNamespace(this.element, TOKEN.getNamespaceURI(), TrustConstants.WST_PREFIX);
        this.element.appendChild(doc.createTextNode(""));
        log.debug("RequestedProofToken : Document constructor, Element created.");
    }

    /**
     * COnstructor
     *
     * @param elem
     * @throws WSSecurityException
     */
    public RequestedProofToken(Element elem) throws WSSecurityException {
        this.element = elem;
        QName el = new QName(this.element.getNamespaceURI(),
                this.element.getLocalName());
        if (!el.equals(TOKEN)) {
            throw new WSSecurityException(WSSecurityException.INVALID_SECURITY_TOKEN,
                    "badTokenType00", new Object[]{el});
        }

        log.debug("RequestedProofToken :: Element constructor, Element created.");
    }

    /**
     * Method doDecryption
     *
     * @param callback
     * @param crypto
     * @throws WSSecurityException
     */
    public void doDecryption(String callback, Crypto crypto)
            throws WSSecurityException {
        WSSecurityEngine secEngine = new WSSecurityEngine();
        CallbackHandler cbHandler;

        // Element
        NodeList ndList =
                this.element.getElementsByTagNameNS("http://www.w3.org/2001/04/xmlenc#",
                        "EncryptedKey");
        if (ndList.getLength() < 1) {
            throw new WSSecurityException(WSSecurityException.SECURITY_TOKEN_UNAVAILABLE,
                    "RequestedProofToken is empty");
        }

        // CbHandler :: taken from WSSecurityEngine class
        if (callback != null) {
            Class cbClass = null;
            try {
                cbClass = Loader.loadClass(callback);
            } catch (ClassNotFoundException e) {
                throw new WSSecurityException(WSSecurityException.FAILED_ENC_DEC,
                        "RequestedProofToken: cannot load password callback class: "
                        + callback);
            }
            try {
                cbHandler = (CallbackHandler) cbClass.newInstance();
            } catch (java.lang.Exception e) {
                throw new WSSecurityException(WSSecurityException.FAILED_ENC_DEC,
                        "RequestedProofToken: cannot create instance of password callback: "
                        + callback +":: ErrMsg "+e.getMessage());
            }
            EncryptedKeyProcessor processor = new EncryptedKeyProcessor();
            processor.handleEncryptedKey((Element) ndList.item(0),
                    cbHandler,
                    crypto);

            this.sharedSecret = processor.getDecryptedBytes();
            log.debug(" RequestedProofToken, decryption ,Shared secret is :: " + new String(this.sharedSecret));
        } else {
            log.debug("RequestedProofToken :: CallbackHandler is null");
            throw new WSSecurityException(WSSecurityException.FAILURE, "CallbackHandler is null");
        }
        log.debug("RequestedProofToken :: Encryption done");
    }

    /**
     * Method doEncryptProof
     *
     * @param doc
     */
    //TODO :: Change the method signature.
    public void doEncryptProof(Document doc, Crypto crypto, String userInfo) throws WSSecurityException {
        WSEncryptBody wsEncrypt = new WSEncryptBody();
        try {
            wsEncrypt.setUserInfo(userInfo);
            wsEncrypt.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
            wsEncrypt.setParentNode(this.element);
            if (this.sharedSecret != null) {
                //wsEncrypt.setSymmetricKey(WSSecurityUtil.prepareSecretKey(WSConstants.TRIPLE_DES, this.sharedSecret));//TODO
            }
//            wsEncrypt.setParentNode(
//                (Element) (doc
//                    .getElementsByTagNameNS(
//                        WSConstants.WSSE_NS,
//                        "RequestedProofToken")
//                    .item(0)));
            wsEncrypt.build(doc, crypto);
            this.sharedSecret = wsEncrypt.getEncryptionKey().getEncoded();
        } catch (WSSecurityException e) {
            e.printStackTrace();
        }
        log.debug("RequestedProofToken :: Decryption Done");
    }

    public Element getElement() {
        return element;
    }

    public void setElement(Element element) {
        this.element = element;
    }

    public String toString() {
        return DOM2Writer.nodeToString((Node) this.element);
    }

    public void addToken(Element childToken) {
        this.element.appendChild(childToken);
    }

    public void removeToken(Element childToken) {
        this.element.removeChild(childToken);
    }

    /**
     * @return
     */
    public byte[] getSharedSecret() {
        return sharedSecret;
    }

    /**
     * @param bs
     */
    public void setSharedSecret(byte[] bs) {
        sharedSecret = bs;
    }

    public Document build(Document doc, Crypto crypto, String user, Element parentNode) throws WSSecurityException {
        boolean doDebug = log.isDebugEnabled();
        //TODO
        int keyIdentifierType = WSConstants.ISSUER_SERIAL;
        SecretKey symmetricKey = null;
        String symEncAlgo = WSConstants.TRIPLE_DES;
        String keyEncAlgo = WSConstants.KEYTRANSPORT_RSA15;

        if (doDebug) {
            log.debug("Beginning Encryption...");
        }

        /*
         * First step: set the encryption encoding namespace in the SOAP:Envelope
         */
        Element envelope = doc.getDocumentElement();
        envelope.setAttributeNS(WSConstants.XMLNS_NS,
                "xmlns:" + WSConstants.ENC_PREFIX,
                WSConstants.ENC_NS);

        SOAPConstants soapConstants = WSSecurityUtil.getSOAPConstants(envelope);

        /*
         * Second step: generate a symmetric key (session key) for
         * this alogrithm, and set the cipher into encryption mode.
         */
        KeyGenerator keyGen = null;
        try {
            keyGen = keyGen = KeyGenerator.getInstance("DESede");
        } catch (NoSuchAlgorithmException e2) {
            // TODO Auto-generated catch block
            e2.printStackTrace();
        }
        symmetricKey = keyGen.generateKey();
        XMLCipher xmlCipher = null;
        try {
            xmlCipher = XMLCipher.getInstance(symEncAlgo);
        } catch (XMLEncryptionException e3) {
            throw new WSSecurityException(WSSecurityException.UNSUPPORTED_ALGORITHM, null, null, e3);
        }


        /*
         * Fifth step: get the certificate that contains the public key for the
         * public key algorithm that will encrypt
         * the generated symmetric (session) key.
         * Up to now we support RSA 1-5 as public key algorithm
         */

        X509Certificate remoteCert = null;
        X509Certificate[] certs = crypto.getCertificates(user);
        if (certs == null || certs.length <= 0) {
            throw new WSSecurityException(WSSecurityException.FAILURE,
                    "invalidX509Data",
                    new Object[]{"for Encryption"});
        }
        remoteCert = certs[0];

        String certUri = "EncCertId-" + remoteCert.hashCode();

        Cipher cipher = null;//TODO
        //Cipher cipher = WSSecurityUtil.getCiperInstance(keyEncAlgo);//TODO
        try {
            cipher.init(Cipher.ENCRYPT_MODE, remoteCert);
        } catch (InvalidKeyException e) {
            throw new WSSecurityException(WSSecurityException.FAILED_ENC_DEC, null, null, e);
        }
        byte[] encKey = symmetricKey.getEncoded();
        if (doDebug) {
            log.debug("cipher blksize: "
                    + cipher.getBlockSize()
                    + ", symm key length: "
                    + encKey.length);
        }
        if (cipher.getBlockSize() < encKey.length) {
            throw new WSSecurityException(WSSecurityException.FAILURE,
                    "unsupportedKeyTransp",
                    new Object[]{"public key algorithm too weak to encrypt symmetric key"});
        }
        byte[] encryptedKey = null;
        try {
            encryptedKey = cipher.doFinal(encKey);
        } catch (IllegalStateException e1) {
            throw new WSSecurityException(WSSecurityException.FAILED_ENC_DEC, null, null, e1);
        } catch (IllegalBlockSizeException e1) {
            throw new WSSecurityException(WSSecurityException.FAILED_ENC_DEC, null, null, e1);
        } catch (BadPaddingException e1) {
            throw new WSSecurityException(WSSecurityException.FAILED_ENC_DEC, null, null, e1);
        }
        Text keyText =
                WSSecurityUtil.createBase64EncodedTextNode(doc, encryptedKey);

        Element xencEncryptedKey = WSEncryptBody.createEnrcyptedKey(doc, keyEncAlgo);

        WSSecurityUtil.prependChildElement(doc,
                parentNode,
                xencEncryptedKey,
                true);

        SecurityTokenReference secToken = null;//new SecurityTokenReference(doc); TODO

        switch (keyIdentifierType) {
            case WSConstants.X509_KEY_IDENTIFIER:
                secToken.setKeyIdentifier(remoteCert);
                // build a key id class??
                break;

            case WSConstants.SKI_KEY_IDENTIFIER:
                secToken.setKeyIdentifierSKI(remoteCert, crypto);
                break;

            case WSConstants.ISSUER_SERIAL:
                XMLX509IssuerSerial data = new XMLX509IssuerSerial(doc, remoteCert);
                X509Data x509Data = new X509Data(doc); 
                x509Data.add(data);
                secToken.setX509IssuerSerial(x509Data);
                WSSecurityUtil.setNamespace(secToken.getElement(), WSConstants.WSSE_NS, WSConstants.WSSE_PREFIX);
                break;

            case WSConstants.BST_DIRECT_REFERENCE:
                BinarySecurity bstToken = null;
                bstToken = new X509Security(doc);
                ((X509Security) bstToken).setX509Certificate(remoteCert);
                bstToken.setID(certUri);
                Reference ref = new Reference(doc);
                ref.setURI("#" + certUri);
                ref.setValueType(bstToken.getValueType());
                secToken.setReference(ref);
//                WSSecurityUtil.prependChildElement(
//                    doc,
//                    wsseSecurity,
//                    bstToken.getElement(),
//                    false);
                break;

            default :
                throw new WSSecurityException(WSSecurityException.FAILURE,
                        "unsupportedKeyId");
        }
        KeyInfo keyInfo = new KeyInfo(doc);
        keyInfo.addUnknownElement(secToken.getElement());
        WSSecurityUtil.appendChildElement(doc, xencEncryptedKey, keyInfo.getElement());

        Element xencCipherValue = WSEncryptBody.createCipherValue(doc, xencEncryptedKey);
        xencCipherValue.appendChild(keyText);
        //    createDataRefList(doc, xencEncryptedKey, encDataRefs);
        log.debug("Encryption complete.");
        return doc;
    }

}
