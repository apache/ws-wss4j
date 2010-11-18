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

package org.apache.ws.security.processor;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSDataRef;
import org.apache.ws.security.WSDocInfo;
import org.apache.ws.security.WSPasswordCallback;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.message.token.SecurityTokenReference;
import org.apache.ws.security.message.token.X509Security;
import org.apache.ws.security.util.Base64;
import org.apache.ws.security.util.WSSecurityUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.Text;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.xml.namespace.QName;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Vector;

public class EncryptedKeyProcessor implements Processor {
    private static Log log = LogFactory.getLog(EncryptedKeyProcessor.class.getName());
    private static Log tlog =
            LogFactory.getLog("org.apache.ws.security.TIME");
    private byte[] encryptedEphemeralKey;
    
    private byte[] decryptedBytes = null;
    
    private String encryptedKeyId = null;
    private X509Certificate[] certs;
    
    private String encryptedKeyTransportMethod = null;
    
    private WSDocInfo docInfo = null;

    public void handleToken(
        Element elem, 
        Crypto crypto, 
        Crypto decCrypto, 
        CallbackHandler cb, 
        WSDocInfo wsDocInfo,
        List<WSSecurityEngineResult> returnResults, 
        WSSConfig wsc
    ) throws WSSecurityException {
        if (log.isDebugEnabled()) {
            log.debug("Found encrypted key element");
        }
        certs = null;
        if (decCrypto == null) {
            throw new WSSecurityException(WSSecurityException.FAILURE, "noDecCryptoFile");
        }
        if (cb == null) {
            throw new WSSecurityException(WSSecurityException.FAILURE, "noCallback");
        }
        docInfo = wsDocInfo;
        List<WSDataRef> dataRefs = handleEncryptedKey(elem, cb, decCrypto, null);
        encryptedKeyId = elem.getAttribute("Id");
        
        WSSecurityEngineResult result = new WSSecurityEngineResult(
                WSConstants.ENCR, 
                decryptedBytes,
                encryptedEphemeralKey,
                encryptedKeyId, 
                dataRefs,
                certs
            );
        
        result.put(
            WSSecurityEngineResult.TAG_ENCRYPTED_KEY_TRANSPORT_METHOD, 
            this.encryptedKeyTransportMethod
        );
        
        returnResults.add(
            0, 
            result
        );
    }

    public List<WSDataRef> handleEncryptedKey(
        Element xencEncryptedKey,
        CallbackHandler cb, 
        Crypto crypto
    ) throws WSSecurityException {
        return handleEncryptedKey(xencEncryptedKey, cb, crypto, null);
    }

    public List<WSDataRef> handleEncryptedKey(
        Element xencEncryptedKey,
        PrivateKey privatekey
    ) throws WSSecurityException {
        return handleEncryptedKey(xencEncryptedKey, null, null, privatekey);
    }

    public List<WSDataRef> handleEncryptedKey(
        Element xencEncryptedKey,
        CallbackHandler cb, 
        Crypto crypto, 
        PrivateKey privateKey
    ) throws WSSecurityException {
        long t0 = 0, t1 = 0, t2 = 0;
        if (tlog.isDebugEnabled()) {
            t0 = System.currentTimeMillis();
        }
        Document doc = xencEncryptedKey.getOwnerDocument();
        //
        // lookup xenc:EncryptionMethod, get the Algorithm attribute to determine
        // how the key was encrypted. Then check if we support the algorithm
        //
        this.encryptedKeyTransportMethod = X509Util.getEncAlgo(xencEncryptedKey);
        Cipher cipher = WSSecurityUtil.getCipherInstance(this.encryptedKeyTransportMethod);
        //
        // Now lookup CipherValue.
        //
        Element tmpE = 
            WSSecurityUtil.getDirectChildElement(
                xencEncryptedKey, "CipherData", WSConstants.ENC_NS
            );
        Element xencCipherValue = null;
        if (tmpE != null) {
            xencCipherValue = 
                WSSecurityUtil.getDirectChildElement(tmpE, "CipherValue", WSConstants.ENC_NS);
        }
        if (xencCipherValue == null) {
            throw new WSSecurityException(WSSecurityException.INVALID_SECURITY, "noCipher");
        }

        if (privateKey == null) {
            privateKey = getPrivateKeyFromKeyInfo(xencEncryptedKey, crypto, doc, cb);
        }

        try {
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
        } catch (Exception ex) {
            throw new WSSecurityException(WSSecurityException.FAILED_CHECK, null, null, ex);
        }

        try {
            encryptedEphemeralKey = getDecodedBase64EncodedData(xencCipherValue);
            decryptedBytes = cipher.doFinal(encryptedEphemeralKey);
        } catch (IllegalStateException ex) {
            throw new WSSecurityException(WSSecurityException.FAILED_CHECK, null, null, ex);
        } catch (IllegalBlockSizeException ex) {
            throw new WSSecurityException(WSSecurityException.FAILED_CHECK, null, null, ex);
        } catch (BadPaddingException ex) {
            throw new WSSecurityException(WSSecurityException.FAILED_CHECK, null, null, ex);
        }

        if (tlog.isDebugEnabled()) {
            t1 = System.currentTimeMillis();
        }
        //
        // At this point we have the decrypted session (symmetric) key. According
        // to W3C XML-Enc this key is used to decrypt _any_ references contained in
        // the reference list
        // Now lookup the references that are encrypted with this key
        //
        Element refList = 
            WSSecurityUtil.getDirectChildElement(
                xencEncryptedKey, "ReferenceList", WSConstants.ENC_NS
            );
        List<WSDataRef> dataRefs = new Vector<WSDataRef>();
        if (refList != null) {
            for (Node node = refList.getFirstChild();
                node != null; 
                node = node.getNextSibling()
            ) {
                if (Node.ELEMENT_NODE == node.getNodeType()
                    && WSConstants.ENC_NS.equals(node.getNamespaceURI())
                    && "DataReference".equals(node.getLocalName())) {
                    String dataRefURI = ((Element) node).getAttribute("URI");
                    if (dataRefURI.charAt(0) == '#') {
                        dataRefURI = dataRefURI.substring(1);
                    }
                    WSDataRef dataRef = decryptDataRef(doc, dataRefURI, decryptedBytes);
                    dataRefs.add(dataRef);
                }
            }
            return dataRefs;
        }

        if (tlog.isDebugEnabled()) {
            t2 = System.currentTimeMillis();
            tlog.debug(
                "XMLDecrypt: total= " + (t2 - t0) + ", get-sym-key= " + (t1 - t0) 
                + ", decrypt= " + (t2 - t1)
            );
        }
        
        return null;
    }

    /**
     * Method getDecodedBase64EncodedData
     *
     * @param element
     * @return a byte array containing the decoded data
     * @throws WSSecurityException
     */
    public static byte[] getDecodedBase64EncodedData(Element element) throws WSSecurityException {
        StringBuffer sb = new StringBuffer();
        Node node = element.getFirstChild();
        while (node != null) {
            if (Node.TEXT_NODE == node.getNodeType()) {
                sb.append(((Text) node).getData());
            }
            node = node.getNextSibling();
        }
        String encodedData = sb.toString();
        return Base64.decode(encodedData);
    }
    
    /**
     * @return the private key corresponding to the public key reference in the 
     * EncryptedKey Element
     */
    private PrivateKey getPrivateKeyFromKeyInfo(
        Element xencEncryptedKey,
        Crypto crypto,
        Document doc,
        CallbackHandler cb
    ) throws WSSecurityException {
        Element keyInfo = 
            WSSecurityUtil.getDirectChildElement(
                xencEncryptedKey, "KeyInfo", WSConstants.SIG_NS
            );
        String alias = null;
        if (keyInfo != null) {
            alias = getAliasFromKeyInfo(keyInfo, crypto, doc, cb);
        } else if (crypto.getDefaultX509Alias() != null) {
            alias = crypto.getDefaultX509Alias();
        } else {
            throw new WSSecurityException(WSSecurityException.INVALID_SECURITY, "noKeyinfo");
        }
        //
        // If the alias is null then throw an Exception, as the private key doesn't exist
        // in our key store
        //
        if (alias == null) {
            throw new WSSecurityException(WSSecurityException.FAILED_CHECK, "noPrivateKey");
        }
        //
        // At this point we have all information necessary to decrypt the session
        // key:
        // - the Cipher object intialized with the correct methods
        // - The data that holds the encrypted session key
        // - the alias name for the private key
        //
        // Now use the callback here to get password that enables
        // us to read the private key
        //
        WSPasswordCallback pwCb = new WSPasswordCallback(alias, WSPasswordCallback.DECRYPT);
        try {
            cb.handle(new Callback[]{pwCb});
        } catch (IOException e) {
            throw new WSSecurityException(
                WSSecurityException.FAILURE,
                "noPassword",
                new Object[]{alias}, 
                e
            );
        } catch (UnsupportedCallbackException e) {
            throw new WSSecurityException(
                WSSecurityException.FAILURE,
                "noPassword",
                new Object[]{alias}, 
                e
            );
        }
        String password = pwCb.getPassword();
        if (password == null) {
            throw new WSSecurityException(
                WSSecurityException.FAILURE, "noPassword", new Object[]{alias}
            );
        }

        try {
            return crypto.getPrivateKey(alias, password);
        } catch (Exception e) {
            throw new WSSecurityException(WSSecurityException.FAILED_CHECK, null, null, e);
        }
    }
    
    
    /**
     * @return Get the alias of the public key from the KeyInfo element
     */
    private String getAliasFromKeyInfo(
        Element keyInfo,
        Crypto crypto,
        Document doc,
        CallbackHandler cb
    ) throws WSSecurityException {
        Element secRefToken = 
            WSSecurityUtil.getDirectChildElement(
                keyInfo, "SecurityTokenReference", WSConstants.WSSE_NS
            );
        //
        // EncryptedKey must have a STR as child of KeyInfo, KeyName  
        // valid only for EncryptedData
        //
        //  if (secRefToken == null) {
        //      secRefToken = (Element) WSSecurityUtil.getDirectChild(keyInfo,
        //              "KeyName", WSConstants.SIG_NS);
        //  }
        if (secRefToken == null) {
            throw new WSSecurityException(
                WSSecurityException.INVALID_SECURITY, "noSecTokRef"
            );
        }
        SecurityTokenReference secRef = new SecurityTokenReference(secRefToken);
        //
        // Well, at this point there are several ways to get the key.
        // Try to handle all of them :-).
        //
        String alias = null;
        //
        // handle X509IssuerSerial here. First check if all elements are available,
        // get the appropriate data, check if all data is available.
        // If all is ok up to that point, look up the certificate alias according
        // to issuer name and serial number.
        // This method is recommended by OASIS WS-S specification, X509 profile
        //
        if (secRef.containsX509Data() || secRef.containsX509IssuerSerial()) {
            alias = secRef.getX509IssuerSerialAlias(crypto);
            if (log.isDebugEnabled()) {
                log.debug("X509IssuerSerial alias: " + alias);
            }
        }
        //
        // If wsse:KeyIdentifier found, then the public key of the attached cert was used to
        // encrypt the session (symmetric) key that encrypts the data. Extract the certificate
        // using the BinarySecurity token (was enhanced to handle KeyIdentifier too).
        // This method is _not_ recommended by OASIS WS-S specification, X509 profile
        //
        else if (secRef.containsKeyIdentifier()) {
            certs = secRef.getKeyIdentifier(crypto);
            if (certs == null || certs.length < 1 || certs[0] == null) {
                throw new WSSecurityException(
                    WSSecurityException.FAILURE,
                    "noCertsFound", 
                    new Object[] {"decryption (KeyId)"}
                );
            }
            //
            // Here we have the certificate. Now find the alias for it. Needed to identify
            // the private key associated with this certificate
            //
            alias = crypto.getAliasForX509Cert(certs[0]);
            if (log.isDebugEnabled()) {
                log.debug("cert: " + certs[0]);
                log.debug("KeyIdentifier Alias: " + alias);
            }
        } else if (secRef.containsReference()) {
            if (docInfo != null) {
                String uri = secRef.getReference().getURI();
                if (uri.charAt(0) == '#') {
                    uri = uri.substring(1);
                }
                Processor processor = docInfo.getProcessor(uri);
                if (processor instanceof BinarySecurityTokenProcessor) {
                    certs = ((BinarySecurityTokenProcessor)processor).getCertificates();
                } else if (processor != null) {
                    throw new WSSecurityException(
                        WSSecurityException.UNSUPPORTED_SECURITY_TOKEN,
                        "unsupportedBinaryTokenType",
                        null
                    );
                }
            }
            if (certs == null) {
                Element bstElement = secRef.getTokenElement(doc, null, cb);
    
                // at this point ... check token type: Binary
                QName el = new QName(bstElement.getNamespaceURI(), bstElement.getLocalName());
                if (el.equals(WSSecurityEngine.BINARY_TOKEN)) {
                    X509Security token = new X509Security(bstElement);
                    if (token == null) {
                        throw new WSSecurityException(
                            WSSecurityException.UNSUPPORTED_SECURITY_TOKEN,
                            "unsupportedBinaryTokenType",
                            new Object[] {"for decryption (BST)"}
                        );
                    }
                    certs = new X509Certificate[]{token.getX509Certificate(crypto)};
                } else {
                    throw new WSSecurityException(
                        WSSecurityException.UNSUPPORTED_SECURITY_TOKEN,
                        "unsupportedBinaryTokenType",
                        null
                    );
                }
            }
            if (certs == null || certs[0] == null) {
                throw new WSSecurityException(
                    WSSecurityException.FAILURE,
                    "noCertsFound", 
                    new Object[] {"decryption"}
                );
            }
            //
            // Here we have the certificate. Now find the alias for it. Needed to identify
            // the private key associated with this certificate
            //
            alias = crypto.getAliasForX509Cert(certs[0]);
            if (log.isDebugEnabled()) {
                log.debug("BST Alias: " + alias);
            }
            //
            // The following code is somewhat strange: the called crypto method gets
            // the keyname and searches for a certificate with an issuer's name that is
            // equal to this keyname. No serialnumber is used - IMHO this does
            // not identifies a certificate. In addition neither the WSS4J encryption
            // nor signature methods use this way to identify a certificate. Because of that
            // the next lines of code are disabled.  
            //
          // } else if (secRef.containsKeyName()) {
          //    alias = crypto.getAliasForX509Cert(secRef.getKeyNameValue());
          //    if (log.isDebugEnabled()) {
          //        log.debug("KeyName alias: " + alias);
          //    }
        } else {
            throw new WSSecurityException(
                WSSecurityException.INVALID_SECURITY, "unsupportedKeyId"
            );
        }
        return alias;
    }

    /**
     * Decrypt an EncryptedData element referenced by dataRefURI
     */
    private WSDataRef decryptDataRef(
        Document doc, 
        String dataRefURI, 
        byte[] decryptedData
    ) throws WSSecurityException {
        if (log.isDebugEnabled()) {
            log.debug("found data reference: " + dataRefURI);
        }
        //
        // Find the encrypted data element referenced by dataRefURI
        //
        Element encryptedDataElement = 
            ReferenceListProcessor.findEncryptedDataElement(doc, dataRefURI);
        //
        // Prepare the SecretKey object to decrypt EncryptedData
        //
        String symEncAlgo = X509Util.getEncAlgo(encryptedDataElement);
        SecretKey symmetricKey = 
            WSSecurityUtil.prepareSecretKey(symEncAlgo, decryptedData);

        return ReferenceListProcessor.decryptEncryptedData(
            doc, dataRefURI, encryptedDataElement, symmetricKey, symEncAlgo
        );
    }
    
    
    /**
     * Get the Id of the encrypted key element.
     * 
     * @return The Id string
     */
    public String getId() {
        return encryptedKeyId;
    }
    
    /**
     * Get the decrypted key.
     * 
     * The encrypted key element contains an encrypted session key. The
     * security functions use the session key to encrypt contents of the message
     * with symmetrical encryption methods.
     *  
     * @return The decrypted key.
     */
    public byte[] getDecryptedBytes() {
        return decryptedBytes;
    }

    public byte[] getEncryptedEphemeralKey() {
        return encryptedEphemeralKey;
    }
  
}
