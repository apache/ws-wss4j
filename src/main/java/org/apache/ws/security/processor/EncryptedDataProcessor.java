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

import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSDocInfo;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.util.WSSecurityUtil;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.encryption.XMLEncryptionException;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import javax.crypto.SecretKey;
import javax.security.auth.callback.CallbackHandler;
import javax.xml.namespace.QName;

import java.util.List;

/**
 * This will process incoming <code>xenc:EncryptedData</code> elements.
 * This processor will not be invoked for encrypted content referenced by a 
 * <code>xenc:ReferenceList</code>.
 */
public class EncryptedDataProcessor implements Processor {
    
    public List<WSSecurityEngineResult> handleToken(
        Element elem, 
        Crypto crypto, 
        Crypto decCrypto,
        CallbackHandler cb, 
        WSDocInfo wsDocInfo, 
        WSSConfig config
    ) throws WSSecurityException {
        Element kiElem = 
            WSSecurityUtil.getDirectChildElement(elem, "KeyInfo", WSConstants.SIG_NS);
        if (kiElem == null) {
            throw new WSSecurityException(
                WSSecurityException.UNSUPPORTED_ALGORITHM, "noKeyinfo"
            );
        }
        
        Element encryptedKeyElement = 
            WSSecurityUtil.getDirectChildElement(
                kiElem, WSConstants.ENC_KEY_LN, WSConstants.ENC_NS
            );
        if (encryptedKeyElement == null) {
            throw new WSSecurityException(
                WSSecurityException.UNSUPPORTED_ALGORITHM, "noEncKey"
            );
        }
        EncryptedKeyProcessor encrKeyProc = new EncryptedKeyProcessor();
        List<WSSecurityEngineResult> encrKeyResults = encrKeyProc.handleToken(
            encryptedKeyElement, crypto, decCrypto, cb, wsDocInfo, config
        );
        byte[] symmKey = 
            (byte[])encrKeyResults.get(0).get(WSSecurityEngineResult.TAG_SECRET);
        String encAlgo = X509Util.getEncAlgo(elem);
        SecretKey key = WSSecurityUtil.prepareSecretKey(encAlgo, symmKey);
        
        // initialize Cipher ....
        XMLCipher xmlCipher = null;
        try {
            xmlCipher = XMLCipher.getInstance(encAlgo);
            xmlCipher.init(XMLCipher.DECRYPT_MODE, key);
        } catch (XMLEncryptionException ex) {
            throw new WSSecurityException(
                WSSecurityException.UNSUPPORTED_ALGORITHM, null, null, ex
            );
        }
        Node previousSibling = elem.getPreviousSibling();
        Node parent = elem.getParentNode();
        try {
            xmlCipher.doFinal(elem.getOwnerDocument(), elem, false);
        } catch (Exception e) {
            throw new WSSecurityException(
                WSSecurityException.FAILED_CHECK, null, null, e
            );
        }
        
        if (config != null) {
            // Get hold of the plain text element
            Element decryptedElem;
            if (previousSibling == null) {
                decryptedElem = (Element)parent.getFirstChild();
            } else {
                decryptedElem = (Element)previousSibling.getNextSibling();
            }
            QName el = new QName(decryptedElem.getNamespaceURI(), decryptedElem.getLocalName());
            Processor proc = config.getProcessor(el);
            if (proc != null) {
                List<WSSecurityEngineResult> results = 
                    proc.handleToken(
                        decryptedElem, crypto, decCrypto, cb, wsDocInfo, config
                    );
                encrKeyResults.addAll(0, results);
            }
        }
        return encrKeyResults;
    }

}
