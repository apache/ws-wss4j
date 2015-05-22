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

package org.apache.wss4j.dom.processor;

import java.security.Principal;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.crypto.SecretKey;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import org.apache.wss4j.common.bsp.BSPRule;
import org.apache.wss4j.common.crypto.AlgorithmSuite;
import org.apache.wss4j.common.crypto.AlgorithmSuiteValidator;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.principal.WSDerivedKeyTokenPrincipal;
import org.apache.wss4j.common.util.KeyUtils;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.WSDataRef;
import org.apache.wss4j.dom.WSDocInfo;
import org.apache.wss4j.dom.WSSecurityEngineResult;
import org.apache.wss4j.dom.bsp.BSPEnforcer;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.message.token.SecurityTokenReference;
import org.apache.wss4j.dom.str.STRParser;
import org.apache.wss4j.dom.str.SecurityTokenRefSTRParser;
import org.apache.wss4j.dom.util.EncryptionUtils;
import org.apache.wss4j.dom.util.WSSecurityUtil;
import org.apache.wss4j.dom.util.X509Util;

public class ReferenceListProcessor implements Processor {
    private static final org.slf4j.Logger LOG = 
        org.slf4j.LoggerFactory.getLogger(ReferenceListProcessor.class);
    
    public List<WSSecurityEngineResult> handleToken(
        Element elem, 
        RequestData data, 
        WSDocInfo wsDocInfo 
    ) throws WSSecurityException {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Found reference list element");
        }
        List<WSDataRef> dataRefs = handleReferenceList(elem, data, wsDocInfo);
        WSSecurityEngineResult result = 
            new WSSecurityEngineResult(WSConstants.ENCR, dataRefs);
        String tokenId = elem.getAttributeNS(null, "Id");
        if (!"".equals(tokenId)) {
            result.put(WSSecurityEngineResult.TAG_ID, tokenId);
        }
        wsDocInfo.addTokenElement(elem);
        wsDocInfo.addResult(result);
        return java.util.Collections.singletonList(result);
    }

    /**
     * Dereferences and decodes encrypted data elements.
     * 
     * @param elem contains the <code>ReferenceList</code> to the encrypted
     *             data elements
     */
    private List<WSDataRef> handleReferenceList(
        Element elem, 
        RequestData data,
        WSDocInfo wsDocInfo
    ) throws WSSecurityException {
        List<WSDataRef> dataRefs = new ArrayList<WSDataRef>();
        for (Node node = elem.getFirstChild(); 
            node != null; 
            node = node.getNextSibling()
        ) {
            if (Node.ELEMENT_NODE == node.getNodeType()
                && WSConstants.ENC_NS.equals(node.getNamespaceURI())
                && "DataReference".equals(node.getLocalName())) {
                String dataRefURI = ((Element) node).getAttributeNS(null, "URI");
                if (dataRefURI.charAt(0) == '#') {
                    dataRefURI = dataRefURI.substring(1);
                }
                
                if (wsDocInfo.getResultByTag(WSConstants.ENCR, dataRefURI) == null) {
                    WSDataRef dataRef = 
                        decryptDataRefEmbedded(
                            elem.getOwnerDocument(), dataRefURI, data, wsDocInfo);
                    dataRefs.add(dataRef);
                }
            }
        }
        
        return dataRefs;
    }

    
    /**
     * Decrypt an (embedded) EncryptedData element referenced by dataRefURI.
     */
    private WSDataRef decryptDataRefEmbedded(
        Document doc, 
        String dataRefURI, 
        RequestData data,
        WSDocInfo wsDocInfo
    ) throws WSSecurityException {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Found data reference: " + dataRefURI);
        }
        //
        // Find the encrypted data element referenced by dataRefURI
        //
        Element encryptedDataElement = 
            EncryptionUtils.findEncryptedDataElement(doc, wsDocInfo, dataRefURI);
        
        if (encryptedDataElement != null && data.isRequireSignedEncryptedDataElements()) {
            List<WSSecurityEngineResult> signedResults = 
                wsDocInfo.getResultsByTag(WSConstants.SIGN);
            WSSecurityUtil.verifySignedElement(encryptedDataElement, signedResults);
        }
        //
        // Prepare the SecretKey object to decrypt EncryptedData
        //
        String symEncAlgo = X509Util.getEncAlgo(encryptedDataElement);
        Element keyInfoElement =
                WSSecurityUtil.getDirectChildElement(
                    encryptedDataElement, "KeyInfo", WSConstants.SIG_NS
                );
        // KeyInfo cannot be null
        if (keyInfoElement == null) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY, "noKeyinfo");
        }
        // Check BSP compliance
        checkBSPCompliance(keyInfoElement, symEncAlgo, data.getBSPEnforcer());
        
        //
        // Try to get a security reference token, if none found try to get a
        // shared key using a KeyName.
        //
        Element secRefToken = 
            WSSecurityUtil.getDirectChildElement(
                keyInfoElement, "SecurityTokenReference", WSConstants.WSSE_NS
            );
        SecretKey symmetricKey = null;
        Principal principal = null;
        if (secRefToken == null) {
            symmetricKey = X509Util.getSharedKey(keyInfoElement, symEncAlgo, data.getCallbackHandler());
        } else {
            STRParser strParser = new SecurityTokenRefSTRParser();
            Map<String, Object> parameters = new HashMap<String, Object>();
            parameters.put(SecurityTokenRefSTRParser.SIGNATURE_METHOD, symEncAlgo);
            strParser.parseSecurityTokenReference(
                secRefToken, data,
                wsDocInfo, parameters
            );
            byte[] secretKey = strParser.getSecretKey();
            principal = strParser.getPrincipal();
            symmetricKey = KeyUtils.prepareSecretKey(symEncAlgo, secretKey);
        }
        
        // Check for compliance against the defined AlgorithmSuite
        AlgorithmSuite algorithmSuite = data.getAlgorithmSuite();
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

            algorithmSuiteValidator.checkSymmetricKeyLength(symmetricKey.getEncoded().length);
            algorithmSuiteValidator.checkSymmetricEncryptionAlgorithm(symEncAlgo);
        }

        return 
            EncryptionUtils.decryptEncryptedData(
                doc, dataRefURI, encryptedDataElement, symmetricKey, symEncAlgo, data
            );
    }
    
    /**
     * Check for BSP compliance
     * @param keyInfoElement The KeyInfo element child
     * @param encAlgo The encryption algorithm
     * @throws WSSecurityException
     */
    private static void checkBSPCompliance(
        Element keyInfoElement, 
        String encAlgo,
        BSPEnforcer bspEnforcer
    ) throws WSSecurityException {
        // We can only have one token reference
        int result = 0;
        Node node = keyInfoElement.getFirstChild();
        Element child = null;
        while (node != null) {
            if (Node.ELEMENT_NODE == node.getNodeType()) {
                result++;
                child = (Element)node;
            }
            node = node.getNextSibling();
        }
        if (result != 1) {
            bspEnforcer.handleBSPRule(BSPRule.R5424);
        }
        
        if (child == null || !WSConstants.WSSE_NS.equals(child.getNamespaceURI()) || 
            !SecurityTokenReference.SECURITY_TOKEN_REFERENCE.equals(child.getLocalName())) {
            bspEnforcer.handleBSPRule(BSPRule.R5426);
        }
        
        // EncryptionAlgorithm cannot be null
        if (encAlgo == null) {
            bspEnforcer.handleBSPRule(BSPRule.R5601);
        }
        // EncryptionAlgorithm must be 3DES, or AES128, or AES256
        if (!WSConstants.TRIPLE_DES.equals(encAlgo)
            && !WSConstants.AES_128.equals(encAlgo)
            && !WSConstants.AES_128_GCM.equals(encAlgo)
            && !WSConstants.AES_256.equals(encAlgo)
            && !WSConstants.AES_256_GCM.equals(encAlgo)) {
            bspEnforcer.handleBSPRule(BSPRule.R5620);
        }
    }

}

