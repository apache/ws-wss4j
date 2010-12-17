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
import org.apache.ws.security.saml.SAMLKeyInfo;
import org.apache.ws.security.saml.SAMLUtil;
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
import java.util.ArrayList;
import java.util.List;

public class EncryptedKeyProcessor implements Processor {
    private static Log log = LogFactory.getLog(EncryptedKeyProcessor.class.getName());
    
    public List<WSSecurityEngineResult> handleToken(
        Element elem, 
        Crypto crypto, 
        Crypto decCrypto, 
        CallbackHandler cb, 
        WSDocInfo wsDocInfo,
        WSSConfig wsc
    ) throws WSSecurityException {
        if (log.isDebugEnabled()) {
            log.debug("Found encrypted key element");
        }
        if (decCrypto == null) {
            throw new WSSecurityException(WSSecurityException.FAILURE, "noDecCryptoFile");
        }
        if (cb == null) {
            throw new WSSecurityException(WSSecurityException.FAILURE, "noCallback");
        }
        //
        // lookup xenc:EncryptionMethod, get the Algorithm attribute to determine
        // how the key was encrypted. Then check if we support the algorithm
        //
        String encryptedKeyTransportMethod = X509Util.getEncAlgo(elem);
        Cipher cipher = WSSecurityUtil.getCipherInstance(encryptedKeyTransportMethod);
        //
        // Now lookup CipherValue.
        //
        Element tmpE = 
            WSSecurityUtil.getDirectChildElement(
                elem, "CipherData", WSConstants.ENC_NS
            );
        Element xencCipherValue = null;
        if (tmpE != null) {
            xencCipherValue = 
                WSSecurityUtil.getDirectChildElement(tmpE, "CipherValue", WSConstants.ENC_NS);
        }
        if (xencCipherValue == null) {
            throw new WSSecurityException(WSSecurityException.INVALID_SECURITY, "noCipher");
        }
        
        String alias = 
            getAliasFromEncryptedKey(elem, decCrypto, elem.getOwnerDocument(), cb, wsDocInfo);
        PrivateKey privateKey = getPrivateKeyFromKeyInfo(decCrypto, cb, alias);
        X509Certificate[] certs = decCrypto.getCertificates(alias);

        try {
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
        } catch (Exception ex) {
            throw new WSSecurityException(WSSecurityException.FAILED_CHECK, null, null, ex);
        }
        
        byte[] encryptedEphemeralKey = null;
        byte[] decryptedBytes = null;
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

        List<WSDataRef> dataRefs = decryptDataRefs(elem.getOwnerDocument(), elem, decryptedBytes);
        
        WSSecurityEngineResult result = new WSSecurityEngineResult(
                WSConstants.ENCR, 
                decryptedBytes,
                encryptedEphemeralKey,
                dataRefs,
                certs
            );
        result.put(
            WSSecurityEngineResult.TAG_ENCRYPTED_KEY_TRANSPORT_METHOD, 
            encryptedKeyTransportMethod
        );
        result.put(WSSecurityEngineResult.TAG_ID, elem.getAttribute("Id"));
        wsDocInfo.addResult(result);
        return java.util.Collections.singletonList(result);
    }

    /**
     * Method getDecodedBase64EncodedData
     *
     * @param element
     * @return a byte array containing the decoded data
     * @throws WSSecurityException
     */
    public static byte[] getDecodedBase64EncodedData(Element element) throws WSSecurityException {
        StringBuilder sb = new StringBuilder();
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
     * @return the alias corresponding to the public key reference in the 
     * EncryptedKey Element
     */
    private String getAliasFromEncryptedKey(
        Element xencEncryptedKey,
        Crypto crypto,
        Document doc,
        CallbackHandler cb,
        WSDocInfo wsDocInfo
    ) throws WSSecurityException {
        Element keyInfo = 
            WSSecurityUtil.getDirectChildElement(
                xencEncryptedKey, "KeyInfo", WSConstants.SIG_NS
            );
        String alias = null;
        if (keyInfo != null) {
            alias = getAliasFromKeyInfo(keyInfo, crypto, doc, cb, wsDocInfo);
        } else if (crypto.getDefaultX509Alias() != null) {
            alias = crypto.getDefaultX509Alias();
        } else {
            throw new WSSecurityException(WSSecurityException.INVALID_SECURITY, "noKeyinfo");
        }
        return alias;
    }
    
    /**
     * @return the private key corresponding to the public key reference in the 
     * EncryptedKey Element
     */
    private PrivateKey getPrivateKeyFromKeyInfo(
        Crypto crypto,
        CallbackHandler cb,
        String alias
    ) throws WSSecurityException {
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
        CallbackHandler cb,
        WSDocInfo wsDocInfo
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
        X509Certificate[] certs = null;
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
            if (WSConstants.WSS_SAML_KI_VALUE_TYPE.equals(secRef.getKeyIdentifierValueType())) { 
                Element token = 
                    secRef.getKeyIdentifierTokenElement(doc, wsDocInfo, cb);
                
                if (crypto == null) {
                    throw new WSSecurityException(
                        WSSecurityException.FAILURE, "noSigCryptoFile"
                    );
                }
                SAMLKeyInfo samlKi = SAMLUtil.getSAMLKeyInfo(token, crypto, cb);
                certs = samlKi.getCerts();
            } else {
                certs = secRef.getKeyIdentifier(crypto);
            }
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
            if (wsDocInfo != null) {
                String uri = secRef.getReference().getURI();
                WSSecurityEngineResult result = wsDocInfo.getResult(uri);
                
                if (result != null) {
                    int action = ((Integer)result.get(WSSecurityEngineResult.TAG_ACTION)).intValue();
                    if (WSConstants.BST == action) {
                        certs = 
                            (X509Certificate[])result.get(
                                WSSecurityEngineResult.TAG_X509_CERTIFICATES
                            );
                    } else {
                        throw new WSSecurityException(
                            WSSecurityException.UNSUPPORTED_SECURITY_TOKEN,
                            "unsupportedBinaryTokenType",
                            null
                        );
                    }
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
     * Decrypt all data references
     */
    private List<WSDataRef> decryptDataRefs(
        Document doc, Element xencEncryptedKey, byte[] decryptedBytes
    ) throws WSSecurityException {
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
        List<WSDataRef> dataRefs = new ArrayList<WSDataRef>();
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

        return null;
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
  
}
