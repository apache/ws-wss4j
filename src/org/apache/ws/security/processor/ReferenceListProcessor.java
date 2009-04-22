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

import java.util.ArrayList;
import java.util.List;
import java.util.Vector;

import javax.crypto.SecretKey;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.xml.namespace.QName;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSDataRef;
import org.apache.ws.security.WSDocInfo;
import org.apache.ws.security.WSPasswordCallback;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.message.token.Reference;
import org.apache.ws.security.message.token.SecurityTokenReference;
import org.apache.ws.security.saml.SAMLKeyInfo;
import org.apache.ws.security.saml.SAMLUtil;
import org.apache.ws.security.util.WSSecurityUtil;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.encryption.XMLEncryptionException;
import org.apache.xml.security.utils.Constants;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
public class ReferenceListProcessor implements Processor {
    private static Log log = 
        LogFactory.getLog(ReferenceListProcessor.class.getName());

    private boolean debug = false;
    WSDocInfo wsDocInfo = null;

    public void handleToken(
        Element elem, 
        Crypto crypto, 
        Crypto decCrypto,
        CallbackHandler cb, 
        WSDocInfo wdi, 
        Vector returnResults,
        WSSConfig wsc
    ) throws WSSecurityException {

        debug = log.isDebugEnabled();
        if (debug) {
            log.debug("Found reference list element");
        }
        if (cb == null) {
            throw new WSSecurityException(WSSecurityException.FAILURE, "noCallback");
        }
        wsDocInfo = wdi;
        List uris = handleReferenceList(elem, cb, crypto);
        returnResults.add(
            0,
            new WSSecurityEngineResult(WSConstants.ENCR, uris)
        );
    }

    /**
     * Dereferences and decodes encrypted data elements.
     * 
     * @param elem contains the <code>ReferenceList</code> to the encrypted
     *             data elements
     * @param cb the callback handler to get the key for a key name stored if
     *           <code>KeyInfo</code> inside the encrypted data elements
     */
    private List handleReferenceList(
        Element elem, 
        CallbackHandler cb,
        Crypto crypto
    ) throws WSSecurityException {
        List dataRefUris = new ArrayList();
        for (Node tmpE = elem.getFirstChild(); 
            tmpE != null; 
            tmpE = tmpE.getNextSibling()
        ) {
            if (Node.ELEMENT_NODE == tmpE.getNodeType()
                && WSConstants.ENC_NS.equals(tmpE.getNamespaceURI())
                && "DataReference".equals(tmpE.getLocalName())) {
                String dataRefURI = ((Element) tmpE).getAttribute("URI");
                if (dataRefURI.charAt(0) == '#') {
                    dataRefURI = dataRefURI.substring(1);
                }
                WSDataRef dataRef = new WSDataRef();
                decryptDataRefEmbedded(elem.getOwnerDocument(), dataRefURI, dataRef, cb, crypto);
                dataRefUris.add(dataRef);
            }
        }
        
        return dataRefUris;
    }

    public void decryptDataRefEmbedded(
        Document doc, 
        String dataRefURI, 
        WSDataRef dataRef,
        CallbackHandler cb, 
        Crypto crypto
    ) throws WSSecurityException {

        if (log.isDebugEnabled()) {
            log.debug("Found data reference: " + dataRefURI);
        }
        //
        // Look up the encrypted data. First try wsu:Id="someURI". If no such Id
        // then try the generic lookup to find Id="someURI"
        //
        Element encBodyData = WSSecurityUtil.getElementByWsuId(doc, dataRefURI);
        if (encBodyData == null) {            
            encBodyData = WSSecurityUtil.getElementByGenId(doc, dataRefURI);
        }
        if (encBodyData == null) {
            throw new WSSecurityException(
                WSSecurityException.INVALID_SECURITY, "dataRef", new Object[] {dataRefURI}
            );
        }
        boolean content = X509Util.isContent(encBodyData);

        // Now figure out the encryption algorithm
        String symEncAlgo = X509Util.getEncAlgo(encBodyData);

        Element tmpE = 
            (Element)WSSecurityUtil.findElement(
                encBodyData, "KeyInfo", WSConstants.SIG_NS
            );
        if (tmpE == null) {
            throw new WSSecurityException(WSSecurityException.INVALID_SECURITY, "noKeyinfo");
        }

        //
        // Try to get a security reference token, if none found try to get a
        // shared key using a KeyName.
        //
        Element secRefToken = 
            WSSecurityUtil.getDirectChildElement(
                tmpE, "SecurityTokenReference", WSConstants.WSSE_NS
            );

        SecretKey symmetricKey = null;
        if (secRefToken == null) {
            symmetricKey = X509Util.getSharedKey(tmpE, symEncAlgo, cb);
        } else {
            symmetricKey = getKeyFromSecurityTokenReference(secRefToken, symEncAlgo, crypto, cb);
        }

        // initialize Cipher ....
        XMLCipher xmlCipher = null;
        try {
            xmlCipher = XMLCipher.getInstance(symEncAlgo);
            xmlCipher.init(XMLCipher.DECRYPT_MODE, symmetricKey);
        } catch (XMLEncryptionException e1) {
            throw new WSSecurityException(
                WSSecurityException.UNSUPPORTED_ALGORITHM, null, null, e1
            );
        }

        if (content) {
            encBodyData = (Element) encBodyData.getParentNode();
            dataRef.setName(new QName(encBodyData.getNamespaceURI(), encBodyData.getLocalName()));
        }
            
        try {
            Node parentEncBody = encBodyData.getParentNode();
            final java.util.List before_peers = WSSecurityUtil.listChildren(parentEncBody);
            
            xmlCipher.doFinal(doc, encBodyData, content);
            
            if (parentEncBody.getLocalName().equals(WSConstants.ENCRYPTED_HEADER)
                && parentEncBody.getNamespaceURI().equals(WSConstants.WSSE11_NS)) {
                Node decryptedHeader = parentEncBody.getFirstChild();
                Element decryptedHeaderClone = (Element)decryptedHeader.cloneNode(true);
                String sigId = decryptedHeaderClone.getAttributeNS(WSConstants.WSU_NS, "Id");
                
                if (sigId == null || sigId.equals("")) {
                    String id = ((Element)parentEncBody).getAttributeNS(WSConstants.WSU_NS, "Id");  
                    if (id.charAt(0) == '#') {
                        id = id.substring(1);
                    }
                    String wsuPrefix = 
                        WSSecurityUtil.setNamespace(
                            decryptedHeaderClone, WSConstants.WSU_NS, WSConstants.WSU_PREFIX
                        );
                    decryptedHeaderClone.setAttributeNS(WSConstants.WSU_NS, wsuPrefix + ":Id", id);
                    dataRef.setWsuId(id);
                } else {
                    dataRef.setWsuId(sigId);
                }
                    
                parentEncBody.getParentNode().appendChild(decryptedHeaderClone);
                parentEncBody.getParentNode().removeChild(parentEncBody);
            } 
            
            final List after_peers = WSSecurityUtil.listChildren(parentEncBody);
            final List new_nodes = WSSecurityUtil.newNodes(before_peers, after_peers);
            for (
                final java.util.Iterator pos = new_nodes.iterator();
                pos.hasNext();
            ) {
                Node node = (Node) pos.next();
                if (node instanceof Element) {
                    if(!Constants.SignatureSpecNS.equals(node.getNamespaceURI()) 
                        && node.getAttributes().getNamedItemNS(WSConstants.WSU_NS, "Id") == null) {
                        String wsuPrefix = 
                            WSSecurityUtil.setNamespace(
                                (Element)node, WSConstants.WSU_NS, WSConstants.WSU_PREFIX
                            );
                        ((Element)node).setAttributeNS(
                            WSConstants.WSU_NS, wsuPrefix + ":Id", dataRefURI
                        );
                        dataRef.setWsuId(dataRefURI);                              
                    }
                    dataRef.setName(new QName(node.getNamespaceURI(),node.getLocalName()));
                }
            }

        } catch (Exception e) {
            throw new WSSecurityException(
                WSSecurityException.FAILED_CHECK, null, null, e
            );
        }
    }

    public String getId() {
        return null;
    }

    /**
     * Retrieves a secret key (session key) from a already parsed EncryptedKey
     * element
     * 
     * This method takes a security token reference (STR) element and checks if
     * it contains a Reference element. Then it gets the vale of the URI
     * attribute of the Reference and uses the retrieved value to lookup an
     * EncrypteKey element to get the decrypted session key bytes. Using the
     * algorithm parameter these bytes are converted into a secret key.
     * 
     * This method requires that the EncyrptedKey element is already available,
     * thus requires a strict layout of the security header. This method
     * supports EncryptedKey elements within the same message.
     * 
     * @param secRefToken The element containing the STR
     * @param algorithm A string that identifies the symmetric decryption algorithm
     * @param crypto Crypto instance to obtain key
     * @param cb Callback handler to obtain the key passwords
     * @return The secret key for the specified algorithm
     * @throws WSSecurityException
     */
    private SecretKey getKeyFromSecurityTokenReference(
        Element secRefToken, 
        String algorithm,
        Crypto crypto, 
        CallbackHandler cb
    ) throws WSSecurityException {

        SecurityTokenReference secRef = new SecurityTokenReference(secRefToken);
        byte[] decryptedData = null;

        if (secRef.containsReference()) {
            Reference reference = secRef.getReference();
            String uri = reference.getURI();
            String id = uri;
            if (id.charAt(0) == '#') {
                id = id.substring(1);
            }
            Processor p = wsDocInfo.getProcessor(id);
            if (!(p instanceof EncryptedKeyProcessor
                || p instanceof DerivedKeyTokenProcessor 
                || p instanceof SAMLTokenProcessor)
            ) {
                // Try custom token
                WSPasswordCallback pwcb = 
                    new WSPasswordCallback(id, WSPasswordCallback.CUSTOM_TOKEN);
                try {
                    Callback[] callbacks = new Callback[]{pwcb};
                    cb.handle(callbacks);
                } catch (Exception e) {
                    throw new WSSecurityException(
                        WSSecurityException.FAILURE,
                        "noPassword", 
                        new Object[] {id}, 
                        e
                    );
                }
                decryptedData = pwcb.getKey();
                
                if (decryptedData == null) {
                    throw new WSSecurityException(
                        WSSecurityException.FAILED_CHECK, "unsupportedKeyId"
                    );
                }
            }
            if (p instanceof EncryptedKeyProcessor) {
                EncryptedKeyProcessor ekp = (EncryptedKeyProcessor) p;
                decryptedData = ekp.getDecryptedBytes();
            } else if (p instanceof DerivedKeyTokenProcessor) {
                DerivedKeyTokenProcessor dkp = (DerivedKeyTokenProcessor) p;
                decryptedData = dkp.getKeyBytes(WSSecurityUtil.getKeyLength(algorithm));
            } else if (p instanceof SAMLTokenProcessor) {
                SAMLTokenProcessor samlp = (SAMLTokenProcessor) p;
                SAMLKeyInfo keyInfo = 
                    SAMLUtil.getSAMLKeyInfo(samlp.getSamlTokenElement(), crypto, cb);
                // TODO Handle malformed SAML tokens where they don't have the 
                // secret in them
                decryptedData = keyInfo.getSecret();
            }
        } else if (secRef.containsKeyIdentifier()){
            String sha = secRef.getKeyIdentifierValue();
            WSPasswordCallback pwcb = 
                new WSPasswordCallback(
                    secRef.getKeyIdentifierValue(),
                    null,
                    secRef.getKeyIdentifierValueType(),
                    WSPasswordCallback.ENCRYPTED_KEY_TOKEN
                );
            
            try {
                Callback[] callbacks = new Callback[]{pwcb};
                cb.handle(callbacks);
            } catch (Exception e) {
                throw new WSSecurityException(
                    WSSecurityException.FAILURE,
                    "noPassword", 
                    new Object[] {sha}, 
                    e
                );
            }
            decryptedData = pwcb.getKey();
        } else {
            throw new WSSecurityException(WSSecurityException.FAILED_CHECK, "noReference");
        }
        return WSSecurityUtil.prepareSecretKey(algorithm, decryptedData);
    }
    
}
