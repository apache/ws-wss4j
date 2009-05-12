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
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.encryption.XMLEncryptionException;
import org.apache.xml.security.utils.Constants;
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
import java.util.Vector;

public class EncryptedKeyProcessor implements Processor {
    private static Log log = LogFactory.getLog(EncryptedKeyProcessor.class.getName());
    private static Log tlog =
            LogFactory.getLog("org.apache.ws.security.TIME");
    private byte[] encryptedEphemeralKey;
    
    private byte[] decryptedBytes = null;
    
    private String encryptedKeyId = null;
    private X509Certificate[] certs;

    public void handleToken(
        Element elem, 
        Crypto crypto, 
        Crypto decCrypto, 
        CallbackHandler cb, 
        WSDocInfo wsDocInfo,
        Vector returnResults, 
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
        List dataRefUris = handleEncryptedKey(elem, cb, decCrypto, null);
        encryptedKeyId = elem.getAttribute("Id");
        returnResults.add(
            0, 
            new WSSecurityEngineResult(
                WSConstants.ENCR, 
                decryptedBytes,
                encryptedEphemeralKey,
                encryptedKeyId, 
                dataRefUris,
                certs
            )
        );
    }

    public List handleEncryptedKey(
        Element xencEncryptedKey,
        CallbackHandler cb, 
        Crypto crypto
    ) throws WSSecurityException {
        return handleEncryptedKey(xencEncryptedKey, cb, crypto, null);
    }

    public List handleEncryptedKey(
        Element xencEncryptedKey,
        PrivateKey privatekey
    ) throws WSSecurityException {
        return handleEncryptedKey(xencEncryptedKey, null, null, privatekey);
    }

    public List handleEncryptedKey(
        Element xencEncryptedKey,
        CallbackHandler cb, 
        Crypto crypto, 
        PrivateKey privateKey
    ) throws WSSecurityException {
        long t0 = 0, t1 = 0, t2 = 0;
        if (tlog.isDebugEnabled()) {
            t0 = System.currentTimeMillis();
        }
        // need to have it to find the encrypted data elements in the envelope
        Document doc = xencEncryptedKey.getOwnerDocument();

        // lookup xenc:EncryptionMethod, get the Algorithm attribute to determine
        // how the key was encrypted. Then check if we support the algorithm
        String keyEncAlgo = X509Util.getEncAlgo(xencEncryptedKey);
        Cipher cipher = WSSecurityUtil.getCipherInstance(keyEncAlgo);
        //
        // Well, we can decrypt the session (symmetric) key. Now lookup CipherValue, this is the 
        // value of the encrypted session key (session key usually is a symmetrical key that encrypts
        // the referenced content). This is a 2-step lookup
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
        } catch (Exception e1) {
            throw new WSSecurityException(WSSecurityException.FAILED_CHECK, null, null, e1);
        }

        try {
            encryptedEphemeralKey = getDecodedBase64EncodedData(xencCipherValue);
            decryptedBytes = cipher.doFinal(encryptedEphemeralKey);
        } catch (IllegalStateException e2) {
            throw new WSSecurityException(WSSecurityException.FAILED_CHECK, null, null, e2);
        } catch (IllegalBlockSizeException e2) {
            throw new WSSecurityException(WSSecurityException.FAILED_CHECK, null, null, e2);
        } catch (BadPaddingException e2) {
            throw new WSSecurityException(WSSecurityException.FAILED_CHECK, null, null, e2);
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
        List dataRefs = new ArrayList();
        if (refList != null) {
            for (Node node = refList.getFirstChild();
                node != null; 
                node = node.getNextSibling()
            ) {
                if (Node.ELEMENT_NODE != node.getNodeType()) {
                    continue;
                }
                if (!node.getNamespaceURI().equals(WSConstants.ENC_NS)) {
                    continue;
                }
                if (node.getLocalName().equals("DataReference")) {                   
                    String dataRefURI = ((Element) node).getAttribute("URI");
                    if (dataRefURI.charAt(0) == '#') {
                        dataRefURI = dataRefURI.substring(1);
                    }
                    WSDataRef dataRef = new WSDataRef();
                    Element elt = decryptDataRef(doc, dataRefURI, dataRef, decryptedBytes);
                    dataRef.setName(
                        new javax.xml.namespace.QName(
                            elt.getNamespaceURI(), elt.getLocalName()
                        )
                    );
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
            Callback[] callbacks = new Callback[]{pwCb};
            cb.handle(callbacks);
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
            Element bstElement = secRef.getTokenElement(doc, null, cb);

            // at this point ... check token type: Binary
            QName el = 
                new QName(bstElement.getNamespaceURI(), bstElement.getLocalName());
            if (el.equals(WSSecurityEngine.binaryToken)) {
                X509Security token = new X509Security(bstElement);
                String value = bstElement.getAttribute(WSSecurityEngine.VALUE_TYPE);
                if (!X509Security.X509_V3_TYPE.equals(value) || (token == null)) {
                    throw new WSSecurityException(
                        WSSecurityException.UNSUPPORTED_SECURITY_TOKEN,
                        "unsupportedBinaryTokenType",
                        new Object[] {"for decryption (BST)"}
                    );
                }
                certs = new X509Certificate[1];
                certs[0] = token.getX509Certificate(crypto);
                if (certs[0] == null) {
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
            } else {
                throw new WSSecurityException(
                    WSSecurityException.UNSUPPORTED_SECURITY_TOKEN,
                    "unsupportedBinaryTokenType",
                    null
                );
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

    private Element decryptDataRef(
        Document doc, 
        String dataRefURI, 
        WSDataRef wsDataRef, 
        byte[] decryptedData
    ) throws WSSecurityException {
        if (log.isDebugEnabled()) {
            log.debug("found data reference: " + dataRefURI);
        }
        //
        // Look up the encrypted data. First try wsu:Id="someURI". If no such Id then
        // try the generic lookup to find Id="someURI"
        //
        Element encBodyData = WSSecurityUtil.getElementByWsuId(doc, dataRefURI);
        if (encBodyData == null) {
            encBodyData = WSSecurityUtil.getElementByGenId(doc, dataRefURI);
        }
        if (encBodyData == null) {
            throw new WSSecurityException(
                WSSecurityException.INVALID_SECURITY, "dataRef", new Object[]{dataRefURI}
            );
        }

        boolean content = X509Util.isContent(encBodyData);

        // get the encryption method
        String symEncAlgo = X509Util.getEncAlgo(encBodyData);

        SecretKey symmetricKey = 
            WSSecurityUtil.prepareSecretKey(symEncAlgo, decryptedData);

        // initialize Cipher ....
        XMLCipher xmlCipher = null;
        try {
            xmlCipher = XMLCipher.getInstance(symEncAlgo);
            xmlCipher.init(XMLCipher.DECRYPT_MODE, symmetricKey);
        } catch (XMLEncryptionException e) {
            throw new WSSecurityException(
                WSSecurityException.UNSUPPORTED_ALGORITHM, null, null, e
            );
        }

        if (content) {
            encBodyData = (Element) encBodyData.getParentNode();
        }
        final Node parent = encBodyData.getParentNode();
        final List before_peers = WSSecurityUtil.listChildren(parent);
        try {
            xmlCipher.doFinal(doc, encBodyData, content);
        } catch (Exception e1) {
            throw new WSSecurityException(WSSecurityException.FAILED_CHECK, null, null, e1);
        }
        
        if (parent.getLocalName().equals(WSConstants.ENCRYPTED_HEADER)
            && parent.getNamespaceURI().equals(WSConstants.WSSE11_NS)) {
            
            Node decryptedHeader = parent.getFirstChild();
            Element decryptedHeaderClone = (Element)decryptedHeader.cloneNode(true);            
            String sigId = decryptedHeaderClone.getAttributeNS(WSConstants.WSU_NS, "Id");
            
            if (sigId == null || sigId.equals("")) {
                String id = ((Element)parent).getAttributeNS(WSConstants.WSU_NS, "Id");
                if (id.charAt(0) == '#') {
                    id = id.substring(1);
                }
                
                String wsuPrefix = 
                    WSSecurityUtil.setNamespace(
                        decryptedHeaderClone, WSConstants.WSU_NS, WSConstants.WSU_PREFIX
                    );
                decryptedHeaderClone.setAttributeNS(WSConstants.WSU_NS, wsuPrefix + ":Id", id);
                wsDataRef.setWsuId(id);
            } else {
                wsDataRef.setWsuId(sigId);
            }
            
            parent.getParentNode().appendChild(decryptedHeaderClone);
            parent.getParentNode().removeChild(parent);
        }

        final List after_peers = WSSecurityUtil.listChildren(parent);
        final List new_nodes = WSSecurityUtil.newNodes(before_peers, after_peers);
        for (
            final java.util.Iterator pos = new_nodes.iterator();
            pos.hasNext();
        ) {
            Node node = (Node) pos.next();
            if (node != null && Node.ELEMENT_NODE == node.getNodeType()) {
                if (!Constants.SignatureSpecNS.equals(node.getNamespaceURI()) &&
                        node.getAttributes().getNamedItemNS(WSConstants.WSU_NS, "Id") == null) {
                    String wsuPrefix = 
                        WSSecurityUtil.setNamespace(
                            (Element)node, WSConstants.WSU_NS, WSConstants.WSU_PREFIX
                        );
                    ((Element)node).setAttributeNS(WSConstants.WSU_NS, wsuPrefix + ":Id", dataRefURI);
                    wsDataRef.setWsuId(dataRefURI);
                }
                wsDataRef.setName(new QName(node.getNamespaceURI(),node.getLocalName()));
                
                return (Element) node;
            }
        }
        return encBodyData;
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
