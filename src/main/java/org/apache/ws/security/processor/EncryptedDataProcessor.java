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
import org.apache.ws.security.handler.RequestData;
import org.apache.ws.security.util.WSSecurityUtil;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.encryption.XMLEncryptionException;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import javax.crypto.SecretKey;
import javax.xml.namespace.QName;

import java.util.ArrayList;
import java.util.List;

/**
 * This will process incoming <code>xenc:EncryptedData</code> elements.
 * This processor will not be invoked for encrypted content referenced by a 
 * <code>xenc:ReferenceList</code>.
 */
public class EncryptedDataProcessor implements Processor {
    
    private static org.apache.commons.logging.Log log = 
        org.apache.commons.logging.LogFactory.getLog(EncryptedDataProcessor.class);
    
    public List<WSSecurityEngineResult> handleToken(
        Element elem,
        RequestData request,
        WSDocInfo wsDocInfo
    ) throws WSSecurityException {
        if (log.isDebugEnabled()) {
            log.debug("Found EncryptedData element");
        }
        Element kiElem = 
            WSSecurityUtil.getDirectChildElement(elem, "KeyInfo", WSConstants.SIG_NS);
        // KeyInfo cannot be null
        if (kiElem == null) {
            throw new WSSecurityException(
                WSSecurityException.UNSUPPORTED_ALGORITHM, "noKeyinfo"
            );
        }
        String symEncAlgo = X509Util.getEncAlgo(elem);
        
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
        List<WSSecurityEngineResult> encrKeyResults = 
            encrKeyProc.handleToken(encryptedKeyElement, request, wsDocInfo);
        byte[] symmKey = 
            (byte[])encrKeyResults.get(0).get(WSSecurityEngineResult.TAG_SECRET);
        SecretKey key = WSSecurityUtil.prepareSecretKey(symEncAlgo, symmKey);
        
        // initialize Cipher ....
        XMLCipher xmlCipher = null;
        try {
            xmlCipher = XMLCipher.getInstance(symEncAlgo);
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
        
        WSSConfig wssConfig = request.getWssConfig();
        if (wssConfig != null) {
            // Get hold of the plain text element
            Element decryptedElem;
            if (previousSibling == null) {
                decryptedElem = (Element)parent.getFirstChild();
            } else {
                decryptedElem = (Element)previousSibling.getNextSibling();
            }
            QName el = new QName(decryptedElem.getNamespaceURI(), decryptedElem.getLocalName());
            Processor proc = request.getWssConfig().getProcessor(el);
            if (proc != null) {
                if (log.isDebugEnabled()) {
                    log.debug("Processing decrypted element with: " + proc.getClass().getName());
                }
                List<WSSecurityEngineResult> results = 
                    proc.handleToken(decryptedElem, request, wsDocInfo);
                List<WSSecurityEngineResult> completeResults = 
                    new ArrayList<WSSecurityEngineResult>();
                completeResults.addAll(encrKeyResults);
                completeResults.addAll(0, results);
                return completeResults;
            }
        }
        return encrKeyResults;
    }

}
