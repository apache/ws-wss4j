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

package org.apache.ws.security.processor;

import java.util.ArrayList;
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
import org.w3c.dom.NodeList;

public class ReferenceListProcessor implements Processor {
    private static Log log = 
        LogFactory.getLog(ReferenceListProcessor.class.getName());

    private boolean debug = false;


    WSDocInfo wsDocInfo = null;

    public void handleToken(Element elem, Crypto crypto, Crypto decCrypto,
            CallbackHandler cb, WSDocInfo wdi, Vector returnResults,
            WSSConfig wsc) throws WSSecurityException {

        debug = log.isDebugEnabled();
        if (debug) {
            log.debug("Found reference list element");
        }
        if (cb == null) {
            throw new WSSecurityException(WSSecurityException.FAILURE,
                    "noCallback");
        }
        wsDocInfo = wdi;
        ArrayList uris = handleReferenceList((Element) elem, cb, crypto);
        returnResults.add(0, new WSSecurityEngineResult(WSConstants.ENCR, uris));
    }

    /**
     * Dereferences and decodes encrypted data elements.
     * 
     * @param elem
     *            contains the <code>ReferenceList</code> to the encrypted
     *            data elements
     * @param cb
     *            the callback handler to get the key for a key name stored if
     *            <code>KeyInfo</code> inside the encrypted data elements
     */
    private ArrayList handleReferenceList(Element elem, CallbackHandler cb,
            Crypto crypto) throws WSSecurityException {

        Document doc = elem.getOwnerDocument();

        Node tmpE = null;
        ArrayList dataRefUris = new ArrayList();
        for (tmpE = elem.getFirstChild(); tmpE != null; tmpE = tmpE
                .getNextSibling()) {
            if (tmpE.getNodeType() != Node.ELEMENT_NODE) {
                continue;
            }
            if (!tmpE.getNamespaceURI().equals(WSConstants.ENC_NS)) {
                continue;
            }
            if (tmpE.getLocalName().equals("DataReference")) {
                String dataRefURI = ((Element) tmpE).getAttribute("URI");
                WSDataRef dataRef = new WSDataRef(dataRefURI.substring(1));
                decryptDataRefEmbedded(doc, dataRefURI, dataRef,cb, crypto);
                dataRefUris.add(dataRef);
            }
        }
        
        return dataRefUris;
    }

    public void decryptDataRefEmbedded(Document doc, String dataRefURI, WSDataRef dataRef,
            CallbackHandler cb, Crypto crypto) throws WSSecurityException {

        if (log.isDebugEnabled()) {
            log.debug("Found data reference: " + dataRefURI);
        }
        /*
         * Look up the encrypted data. First try wsu:Id="someURI". If no such Id
         * then try the generic lookup to find Id="someURI"
         */
        Element encBodyData = null;
        if ((encBodyData = WSSecurityUtil.getElementByWsuId(doc, dataRefURI)) == null) {            
            encBodyData = WSSecurityUtil.getElementByGenId(doc, dataRefURI);
        }
        if (encBodyData == null) {
            throw new WSSecurityException(WSSecurityException.INVALID_SECURITY,
                    "dataRef", new Object[] { dataRefURI });
        }

        boolean content = X509Util.isContent(encBodyData);

        // Now figure out the encryption algorithm
        String symEncAlgo = X509Util.getEncAlgo(encBodyData);

        Element tmpE = (Element) WSSecurityUtil.findElement((Node) encBodyData,
                "KeyInfo", WSConstants.SIG_NS);
        if (tmpE == null) {
            throw new WSSecurityException(WSSecurityException.INVALID_SECURITY,
                    "noKeyinfo");
        }

        /*
         * Try to get a security reference token, if none found try to get a
         * shared key using a KeyName.
         */
        Element secRefToken = (Element) WSSecurityUtil.getDirectChild(tmpE,
                "SecurityTokenReference", WSConstants.WSSE_NS);

        SecretKey symmetricKey = null;
        if (secRefToken == null) {
            symmetricKey = X509Util.getSharedKey(tmpE, symEncAlgo, cb);
        } else
            symmetricKey = getKeyFromSecurityTokenReference(secRefToken, symEncAlgo, crypto, cb);

        // initialize Cipher ....
        XMLCipher xmlCipher = null;
        try {
            xmlCipher = XMLCipher.getInstance(symEncAlgo);
            xmlCipher.init(XMLCipher.DECRYPT_MODE, symmetricKey);
        } catch (XMLEncryptionException e1) {
            throw new WSSecurityException(
                    WSSecurityException.UNSUPPORTED_ALGORITHM, null, null, e1);
        }

        if (content) {
            encBodyData = (Element) encBodyData.getParentNode();
        }
            
        try {
            Node parentEncBody =encBodyData.getParentNode();
            
                final java.util.List before_peers = listChildren(parentEncBody);
            
            xmlCipher.doFinal(doc, encBodyData, content);
            
            if(parentEncBody.getLocalName().equals(WSConstants.ENCRYPTED_HEADER)
                    && parentEncBody.getNamespaceURI().equals(WSConstants.WSSE11_NS)) {
                Node decryptedHeader = parentEncBody.getFirstChild();
                Element decryptedHeaderClone = (Element)decryptedHeader.cloneNode(true);
                    String sigId = decryptedHeaderClone.getAttributeNS(WSConstants.WSU_NS, "Id");
                
                    if ( sigId == null || sigId.equals("") ) {
                            String id = ((Element)parentEncBody).getAttributeNS(WSConstants.WSU_NS, "Id");                              
                            String wsuPrefix = WSSecurityUtil.setNamespace(decryptedHeaderClone,
                                        WSConstants.WSU_NS, WSConstants.WSU_PREFIX);
                            decryptedHeaderClone.setAttributeNS(WSConstants.WSU_NS, wsuPrefix + ":Id", id);
                            dataRef.setWsuId(id.substring(1));
                    } else {
                        dataRef.setWsuId(sigId);
                    }
                    
                parentEncBody.getParentNode().appendChild(decryptedHeaderClone);
                parentEncBody.getParentNode().removeChild(parentEncBody);
                
            } 
            
            final java.util.List after_peers = listChildren(parentEncBody);
            final java.util.List new_nodes = newNodes(before_peers, after_peers);

            for (
                final java.util.Iterator pos = new_nodes.iterator();
                pos.hasNext();
            ) {
                Node node = (Node) pos.next();
                if (node instanceof Element) {
                    if(!Constants.SignatureSpecNS.equals(node.getNamespaceURI()) &&
                            node.getAttributes().getNamedItemNS(WSConstants.WSU_NS, "Id") == null) {
                        String wsuPrefix = WSSecurityUtil.setNamespace((Element)node,
                                WSConstants.WSU_NS, WSConstants.WSU_PREFIX);
                        ((Element)node).setAttributeNS(WSConstants.WSU_NS, wsuPrefix + ":Id", dataRefURI);
                        dataRef.setWsuId(dataRefURI.substring(1));                              
                    }
                    dataRef.setName(new QName(node.getNamespaceURI(),node.getLocalName()));
                }
            }

        } catch (Exception e) {
            throw new WSSecurityException(WSSecurityException.FAILED_CHECK,
                    null, null, e);
        }
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.apache.ws.security.processor.Processor#getId()
     * 
     * A reference list does not have an id.
     */
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
     * <p/>
     * 
     * This method requires that the EncyrptedKey element is already available,
     * thus requires a strict layout of the security header. This method
     * supports EncryptedKey elements within the same message.
     * 
     * @param secRefToken
     *            The element containing the STR
     * @param algorithm
     *            A string that identifies the symmetric decryption algorithm
     * @param crypto Crypto instance to obtain key
     * @param cb CAllback handler to obtain the key passwords
     * @return The secret key for the specified algorithm
     * @throws WSSecurityException
     */
    private SecretKey getKeyFromSecurityTokenReference(Element secRefToken, String algorithm,
            Crypto crypto, CallbackHandler cb)
            throws WSSecurityException {

        SecurityTokenReference secRef = new SecurityTokenReference(secRefToken);
        byte[] decryptedData = null;

        if (secRef.containsReference()) {
            Reference reference = secRef.getReference();
            String uri = reference.getURI();
            String id = uri.substring(1);
            Processor p = wsDocInfo.getProcessor(id);
            if (p == null
                    || (!(p instanceof EncryptedKeyProcessor)
                            && !(p instanceof DerivedKeyTokenProcessor) 
                            && !(p instanceof SAMLTokenProcessor))) {
                
                // Try custom token
                WSPasswordCallback pwcb = new WSPasswordCallback(id, WSPasswordCallback.CUSTOM_TOKEN);
                try {
                    cb.handle(new Callback[]{pwcb});
                } catch (Exception e) {
                    throw new WSSecurityException(WSSecurityException.FAILURE,
                            "noPassword", new Object[] { id }, e);
                }
                decryptedData = pwcb.getKey();
                
                if(decryptedData == null) {
                    throw new WSSecurityException(
                        WSSecurityException.FAILED_CHECK, "unsupportedKeyId");
                }
            }
            if(p instanceof EncryptedKeyProcessor) {
                EncryptedKeyProcessor ekp = (EncryptedKeyProcessor) p;
                decryptedData = ekp.getDecryptedBytes();
            } else if(p instanceof DerivedKeyTokenProcessor) {
                DerivedKeyTokenProcessor dkp = (DerivedKeyTokenProcessor) p;
                decryptedData = dkp.getKeyBytes(WSSecurityUtil.getKeyLength(algorithm));
            } else if(p instanceof SAMLTokenProcessor) {
                SAMLTokenProcessor samlp = (SAMLTokenProcessor) p;
                SAMLKeyInfo keyInfo = SAMLUtil.getSAMLKeyInfo(samlp
                        .getSamlTokenElement(), crypto, cb);
                //TODO Handle malformed SAML tokens where they don't have the 
                //secret in them
                decryptedData = keyInfo.getSecret();
            }
        } else if (secRef.containsKeyIdentifier()){
            String sha = secRef.getKeyIdentifierValue();
            WSPasswordCallback pwcb = new WSPasswordCallback(secRef.getKeyIdentifierValue(),
                                                             null,
                                                             secRef.getKeyIdentifierValueType(),
                                                             WSPasswordCallback.ENCRYPTED_KEY_TOKEN);
            
            try {
                cb.handle(new Callback[]{pwcb});
            } catch (Exception e) {
                throw new WSSecurityException(WSSecurityException.FAILURE,
                        "noPassword", new Object[] { sha }, e);
            }
            decryptedData = pwcb.getKey();
        } else {
            throw new WSSecurityException(WSSecurityException.FAILED_CHECK,
                    "noReference");
        }
        return WSSecurityUtil.prepareSecretKey(algorithm, decryptedData);
    }
    
    /**
     * @return      a list of Nodes, representing the 
     */
    private static java.util.List
    listChildren(
        final Node parent
    ) {
        if (parent == null) {
            return java.util.Collections.EMPTY_LIST;
        }
        final java.util.List ret = new java.util.ArrayList();
        if (parent.hasChildNodes()) {
            final NodeList children = parent.getChildNodes();
            if (children != null) {
                for (int i = 0, n = children.getLength();  i < n;  ++i) {
                    ret.add(children.item(i));
                }
            }
        }
        return ret;
    }

    /**
     * @return      a list of Nodes in b that are not in a 
     */
    private static java.util.List
    newNodes(
        final java.util.List a,
        final java.util.List b
    ) {
        if (a.size() == 0) {
            return b;
        }
        if (b.size() == 0) {
            return java.util.Collections.EMPTY_LIST;
        }
        final java.util.List ret = new java.util.ArrayList();
        for (
            final java.util.Iterator bpos = b.iterator();
            bpos.hasNext();
        ) {
            final Node bnode = (Node) bpos.next();
            final java.lang.String bns = bnode.getNamespaceURI();
            final java.lang.String bln = bnode.getLocalName();
            boolean found = false;
            for (
                final java.util.Iterator apos = a.iterator();
                apos.hasNext();
            ) {
                final Node anode = (Node) apos.next();
                final java.lang.String ans = anode.getNamespaceURI();
                final java.lang.String aln = anode.getLocalName();
                final boolean nsmatch =
                    ans == null
                    ? ((bns == null) ? true : false)
                            : ((bns == null) ? false : ans.equals(bns));
                final boolean lnmatch =
                    aln == null
                    ? ((bln == null) ? true : false)
                            : ((bln == null) ? false : aln.equals(bln));
                if (nsmatch && lnmatch) {
                    found = true;
                }
            }
            if (!found) {
                ret.add(bnode);
            }
        }
        return ret;
    }
}
