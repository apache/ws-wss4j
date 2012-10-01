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

import java.security.Principal;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.crypto.SecretKey;
import javax.xml.namespace.QName;

import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSDataRef;
import org.apache.ws.security.WSDerivedKeyTokenPrincipal;
import org.apache.ws.security.WSDocInfo;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.AlgorithmSuite;
import org.apache.ws.security.components.crypto.AlgorithmSuiteValidator;
import org.apache.ws.security.handler.RequestData;
import org.apache.ws.security.str.STRParser;
import org.apache.ws.security.str.SecurityTokenRefSTRParser;
import org.apache.ws.security.util.WSSecurityUtil;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.encryption.XMLEncryptionException;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

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
        // Check BSP compliance
        if (request.getWssConfig().isWsiBSPCompliant()) {
            checkBSPCompliance(symEncAlgo);
        }
        
        // Get the Key either via a SecurityTokenReference or an EncryptedKey
        Element secRefToken = 
            WSSecurityUtil.getDirectChildElement(
                kiElem, "SecurityTokenReference", WSConstants.WSSE_NS
            );
        Element encryptedKeyElement = 
            WSSecurityUtil.getDirectChildElement(
                kiElem, WSConstants.ENC_KEY_LN, WSConstants.ENC_NS
            );
        
        if (elem != null && request.isRequireSignedEncryptedDataElements()) {
            WSSecurityUtil.verifySignedElement(elem, elem.getOwnerDocument(), wsDocInfo.getSecurityHeader());
        }
        
        SecretKey key = null;
        List<WSSecurityEngineResult> encrKeyResults = null;
        Principal principal = null;
        if (secRefToken != null) {
            STRParser strParser = new SecurityTokenRefSTRParser();
            Map<String, Object> parameters = new HashMap<String, Object>();
            parameters.put(SecurityTokenRefSTRParser.SIGNATURE_METHOD, symEncAlgo);
            strParser.parseSecurityTokenReference(
                secRefToken, request,
                wsDocInfo, parameters
            );
            byte[] secretKey = strParser.getSecretKey();
            principal = strParser.getPrincipal();
            key = WSSecurityUtil.prepareSecretKey(symEncAlgo, secretKey);
        } else if (encryptedKeyElement != null) {
            EncryptedKeyProcessor encrKeyProc = new EncryptedKeyProcessor();
            encrKeyResults = encrKeyProc.handleToken(encryptedKeyElement, request, wsDocInfo);
            byte[] symmKey = 
                (byte[])encrKeyResults.get(0).get(WSSecurityEngineResult.TAG_SECRET);
            key = WSSecurityUtil.prepareSecretKey(symEncAlgo, symmKey);
        } else {
            throw new WSSecurityException(
                WSSecurityException.UNSUPPORTED_ALGORITHM, "noEncKey"
            );
        }
        
        // Check for compliance against the defined AlgorithmSuite
        AlgorithmSuite algorithmSuite = request.getAlgorithmSuite();
        if (algorithmSuite != null) {
            AlgorithmSuiteValidator algorithmSuiteValidator = new
                AlgorithmSuiteValidator(algorithmSuite);

            if (principal instanceof WSDerivedKeyTokenPrincipal) {
                algorithmSuiteValidator.checkDerivedKeyAlgorithm(
                    ((WSDerivedKeyTokenPrincipal)principal).getAlgorithm()
                );
                algorithmSuiteValidator.checkEncryptionDerivedKeyLength(
                    ((WSDerivedKeyTokenPrincipal)principal).getLength()
                );
            }
            algorithmSuiteValidator.checkSymmetricKeyLength(key.getEncoded().length);
            algorithmSuiteValidator.checkSymmetricEncryptionAlgorithm(symEncAlgo);
        }
        
        // initialize Cipher ....
        XMLCipher xmlCipher = null;
        try {
            xmlCipher = XMLCipher.getInstance(symEncAlgo);
            xmlCipher.setSecureValidation(true);
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
        
        WSDataRef dataRef = new WSDataRef();
        dataRef.setWsuId(elem.getAttributeNS(null, "Id"));
        dataRef.setAlgorithm(symEncAlgo);
        dataRef.setContent(false);
        
        Node decryptedNode;
        if (previousSibling == null) {
            decryptedNode = parent.getFirstChild();
        } else {
            decryptedNode = previousSibling.getNextSibling();
        }
        if (decryptedNode != null && Node.ELEMENT_NODE == decryptedNode.getNodeType()) {
            dataRef.setProtectedElement((Element)decryptedNode);
        }
        dataRef.setXpath(ReferenceListProcessor.getXPath(decryptedNode));
        
        WSSecurityEngineResult result = 
                new WSSecurityEngineResult(WSConstants.ENCR, Collections.singletonList(dataRef));
        result.put(WSSecurityEngineResult.TAG_ID, elem.getAttributeNS(null, "Id"));
        wsDocInfo.addResult(result);
        wsDocInfo.addTokenElement(elem);
        
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
                if (encrKeyResults != null) {
                    completeResults.addAll(encrKeyResults);
                }
                completeResults.add(result);
                completeResults.addAll(0, results);
                return completeResults;
            }
        }
        encrKeyResults.add(result);
        return encrKeyResults;
    }
    
    /**
     * Check for BSP compliance
     * @param encAlgo The encryption algorithm
     * @throws WSSecurityException
     */
    private static void checkBSPCompliance(
        String encAlgo
    ) throws WSSecurityException {
        // EncryptionAlgorithm cannot be null
        if (encAlgo == null) {
            throw new WSSecurityException(
                WSSecurityException.UNSUPPORTED_ALGORITHM, "noEncAlgo"
            );
        }
        // EncryptionAlgorithm must be 3DES, or AES128, or AES256
        if (!WSConstants.TRIPLE_DES.equals(encAlgo)
            && !WSConstants.AES_128.equals(encAlgo)
            && !WSConstants.AES_128_GCM.equals(encAlgo)
            && !WSConstants.AES_256.equals(encAlgo)
            && !WSConstants.AES_256_GCM.equals(encAlgo)) {
            throw new WSSecurityException(
                WSSecurityException.INVALID_SECURITY, "badEncAlgo", new Object[]{encAlgo}
            );
        }
    }

}
