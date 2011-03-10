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

package org.apache.ws.security.message;

import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSEncryptionPart;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.conversation.ConversationException;
import org.apache.ws.security.message.token.Reference;
import org.apache.ws.security.message.token.SecurityTokenReference;
import org.apache.ws.security.util.WSSecurityUtil;
import org.apache.xml.security.keys.KeyInfo;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import javax.crypto.SecretKey;

import java.util.ArrayList;
import java.util.List;

/**
 * Encrypts and signs parts of a message with derived keys derived from a
 * symmetric key. This symmetric key will be included as an EncryptedKey
 * 
 * @author Ruchith Fernando (ruchith.fernando@gmail.com)
 */
public class WSSecDKEncrypt extends WSSecDerivedKeyBase {

    protected String symEncAlgo = WSConstants.AES_128;
    
    public WSSecDKEncrypt() {
        super();
    }
    public WSSecDKEncrypt(WSSConfig config) {
        super(config);
    }
    
    public Document build(Document doc, WSSecHeader secHeader)
        throws WSSecurityException, ConversationException {
        
        //
        // Setup the encrypted key
        //
        prepare(doc);
        envelope = doc.getDocumentElement();
        //
        // prepend elements in the right order to the security header
        //
        prependDKElementToHeader(secHeader);
                
        String soapNamespace = WSSecurityUtil.getSOAPNamespace(envelope);
        if (parts == null) {
            parts = new ArrayList<WSEncryptionPart>(1);
            WSEncryptionPart encP = 
                new WSEncryptionPart(
                    WSConstants.ELEM_BODY, 
                    soapNamespace, 
                    "Content"
                );
            parts.add(encP);
        }
        Element externRefList = encryptForExternalRef(null, parts);
        addExternalRefElement(externRefList, secHeader);

        return doc;
    }

    /**
     * Encrypt one or more parts or elements of the message (external).
     * 
     * This method takes a vector of <code>WSEncryptionPart</code> object that
     * contain information about the elements to encrypt. The method call the
     * encryption method, takes the reference information generated during
     * encryption and add this to the <code>xenc:Reference</code> element.
     * This method can be called after <code>prepare()</code> and can be
     * called multiple times to encrypt a number of parts or elements.
     * 
     * The method generates a <code>xenc:Reference</code> element that <i>must</i>
     * be added to the SecurityHeader. See <code>addExternalRefElement()</code>.
     * 
     * If the <code>dataRef</code> parameter is <code>null</code> the method
     * creates and initializes a new Reference element.
     * 
     * @param dataRef A <code>xenc:Reference</code> element or <code>null</code>
     * @param references A list containing WSEncryptionPart objects
     * @return Returns the updated <code>xenc:Reference</code> element
     * @throws WSSecurityException
     */
    public Element encryptForExternalRef(Element dataRef, List<WSEncryptionPart> references)
        throws WSSecurityException {
        
        KeyInfo keyInfo = createKeyInfo();
        SecretKey key = WSSecurityUtil.prepareSecretKey(symEncAlgo, derivedKeyBytes);

        List<String> encDataRefs = 
            WSSecEncrypt.doEncryption(
                document, getWsConfig(), keyInfo, key, symEncAlgo, references, callbackLookup
            );
        if (dataRef == null) {
            dataRef = 
                document.createElementNS(
                    WSConstants.ENC_NS, WSConstants.ENC_PREFIX + ":ReferenceList"
                );
        }
        return WSSecEncrypt.createDataRefList(document, dataRef, encDataRefs);
    }
    
    /**
     * Create a KeyInfo object
     */
    private KeyInfo createKeyInfo() throws WSSecurityException {
        KeyInfo keyInfo = new KeyInfo(document);
        SecurityTokenReference secToken = new SecurityTokenReference(document);
        secToken.addWSSENamespace();
        Reference ref = new Reference(document);
        ref.setURI("#" + dktId);
        secToken.setReference(ref);

        keyInfo.addUnknownElement(secToken.getElement());
        Element keyInfoElement = keyInfo.getElement();
        keyInfoElement.setAttributeNS(
            WSConstants.XMLNS_NS, "xmlns:" + WSConstants.SIG_PREFIX, WSConstants.SIG_NS
        );
        
        return keyInfo;
    }
    
    /**
     * Adds (prepends) the external Reference element to the Security header.
     * 
     * The reference element <i>must</i> be created by the
     * <code>encryptForExternalRef() </code> method. The method adds the
     * reference element in the SecurityHeader.
     * 
     * @param referenceList The external <code>enc:Reference</code> element
     * @param secHeader The security header.
     */
    public void addExternalRefElement(Element referenceList, WSSecHeader secHeader) {
        Node node = dkt.getElement().getNextSibling();
        if (node != null && Node.ELEMENT_NODE == node.getNodeType()) {
            secHeader.getSecurityHeader().insertBefore(referenceList, node);
        } else {
            // If (at this moment) DerivedKeyToken is the LAST element of 
            // the security header 
            secHeader.getSecurityHeader().appendChild(referenceList);
        }
    }


    /**
     * Set the symmetric encryption algorithm URI to use
     * @param algo the symmetric encryption algorithm URI to use
     */
    public void setSymmetricEncAlgorithm(String algo) {
        symEncAlgo = algo;
    }

    /**
     * @see org.apache.ws.security.message.WSSecDerivedKeyBase#getDerivedKeyLength()
     */
    protected int getDerivedKeyLength() throws WSSecurityException{
        return (derivedKeyLength > 0) ? derivedKeyLength : 
            WSSecurityUtil.getKeyLength(symEncAlgo);
    }
    
}
