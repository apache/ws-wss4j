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
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import javax.crypto.SecretKey;
import javax.xml.namespace.QName;

import org.apache.wss4j.common.bsp.BSPEnforcer;
import org.apache.wss4j.common.bsp.BSPRule;
import org.apache.wss4j.common.crypto.AlgorithmSuite;
import org.apache.wss4j.common.crypto.AlgorithmSuiteValidator;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.principal.WSDerivedKeyTokenPrincipal;
import org.apache.wss4j.common.util.KeyUtils;
import org.apache.wss4j.common.util.XMLUtils;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.WSDataRef;
import org.apache.wss4j.dom.WSDocInfo;
import org.apache.wss4j.dom.engine.WSSConfig;
import org.apache.wss4j.dom.engine.WSSecurityEngineResult;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.str.STRParser;
import org.apache.wss4j.dom.str.STRParserParameters;
import org.apache.wss4j.dom.str.STRParserResult;
import org.apache.wss4j.dom.str.SecurityTokenRefSTRParser;
import org.apache.wss4j.dom.util.EncryptionUtils;
import org.apache.wss4j.dom.util.SignatureUtils;
import org.apache.wss4j.dom.util.X509Util;
import org.w3c.dom.Element;

/**
 * This will process incoming <code>xenc:EncryptedData</code> elements.
 * This processor will not be invoked for encrypted content referenced by a
 * <code>xenc:ReferenceList</code>.
 */
public class EncryptedDataProcessor implements Processor {

    private static final org.slf4j.Logger LOG =
        org.slf4j.LoggerFactory.getLogger(EncryptedDataProcessor.class);

    public List<WSSecurityEngineResult> handleToken(
        Element elem,
        RequestData request,
        WSDocInfo wsDocInfo
    ) throws WSSecurityException {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Found EncryptedData element");
        }

        final String encryptedDataId = elem.getAttributeNS(null, "Id");

        Element kiElem =
            XMLUtils.getDirectChildElement(elem, "KeyInfo", WSConstants.SIG_NS);
        // KeyInfo cannot be null
        if (kiElem == null) {
            throw new WSSecurityException(
                WSSecurityException.ErrorCode.UNSUPPORTED_ALGORITHM, "noKeyinfo"
            );
        }

        String symEncAlgo = X509Util.getEncAlgo(elem);
        checkBSPCompliance(symEncAlgo, request.getBSPEnforcer());

        // Get the Key either via a SecurityTokenReference or an EncryptedKey
        Element secRefToken =
            XMLUtils.getDirectChildElement(
                kiElem, "SecurityTokenReference", WSConstants.WSSE_NS
            );
        Element encryptedKeyElement =
            XMLUtils.getDirectChildElement(
                kiElem, WSConstants.ENC_KEY_LN, WSConstants.ENC_NS
            );
        Element retrievalMethodElement =
            XMLUtils.getDirectChildElement(
                kiElem, "RetrievalMethod", WSConstants.SIG_NS
            );

        if (request.isRequireSignedEncryptedDataElements()) {
            List<WSSecurityEngineResult> signedResults =
                wsDocInfo.getResultsByTag(WSConstants.SIGN);
            SignatureUtils.verifySignedElement(elem, signedResults);
        }

        SecretKey key = null;
        List<WSSecurityEngineResult> encrKeyResults = null;
        Principal principal = null;
        if (secRefToken != null) {
            STRParserParameters parameters = new STRParserParameters();
            parameters.setData(request);
            parameters.setWsDocInfo(wsDocInfo);
            parameters.setStrElement(secRefToken);
            if (symEncAlgo != null) {
                parameters.setDerivationKeyLength(KeyUtils.getKeyLength(symEncAlgo));
            }

            STRParser strParser = new SecurityTokenRefSTRParser();
            STRParserResult parserResult = strParser.parseSecurityTokenReference(parameters);
            byte[] secretKey = parserResult.getSecretKey();
            principal = parserResult.getPrincipal();
            key = KeyUtils.prepareSecretKey(symEncAlgo, secretKey);
            encrKeyResults = new ArrayList<>();
        } else if (encryptedKeyElement != null && request.getWssConfig() != null) {
            WSSConfig wssConfig = request.getWssConfig();
            Processor encrKeyProc = wssConfig.getProcessor(WSConstants.ENCRYPTED_KEY);
            encrKeyResults = encrKeyProc.handleToken(encryptedKeyElement, request, wsDocInfo);
            byte[] symmKey =
                (byte[])encrKeyResults.get(0).get(WSSecurityEngineResult.TAG_SECRET);
            key = KeyUtils.prepareSecretKey(symEncAlgo, symmKey);
        } else if (retrievalMethodElement != null
            && "http://www.w3.org/2001/04/xmlenc#EncryptedKey".equals(
                retrievalMethodElement.getAttributeNS(null, "Type"))) {
            String uri = retrievalMethodElement.getAttributeNS(null, "URI");
            uri = XMLUtils.getIDFromReference(uri);
            WSSecurityEngineResult result = wsDocInfo.getResult(uri);
            if (result != null) {
                byte[] symmKey = (byte[])result.get(WSSecurityEngineResult.TAG_SECRET);
                key = KeyUtils.prepareSecretKey(symEncAlgo, symmKey);
            }
        } else {
            throw new WSSecurityException(
                WSSecurityException.ErrorCode.UNSUPPORTED_ALGORITHM, "noEncKey"
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

        WSDataRef dataRef = EncryptionUtils.decryptEncryptedData(
                elem.getOwnerDocument(), encryptedDataId, elem, key, symEncAlgo,
                request.getAttachmentCallbackHandler());

        WSSecurityEngineResult result =
                new WSSecurityEngineResult(WSConstants.ENCR, Collections.singletonList(dataRef));
        if (!"".equals(encryptedDataId)) {
            result.put(WSSecurityEngineResult.TAG_ID, encryptedDataId);
        }
        wsDocInfo.addResult(result);
        wsDocInfo.addTokenElement(elem);

        List<WSSecurityEngineResult> completeResults = new LinkedList<>();
        completeResults.addAll(encrKeyResults);
        completeResults.add(result);

        WSSConfig wssConfig = request.getWssConfig();
        if (wssConfig != null) {
            // Get hold of the plain text element
            Element decryptedElem = dataRef.getProtectedElement();
            if (decryptedElem != null) { //is null if we processed an attachment
                QName el = new QName(decryptedElem.getNamespaceURI(), decryptedElem.getLocalName());
                Processor proc = request.getWssConfig().getProcessor(el);
                if (proc != null) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Processing decrypted element with: " + proc.getClass().getName());
                    }
                    List<WSSecurityEngineResult> results =
                            proc.handleToken(decryptedElem, request, wsDocInfo);
                    completeResults.addAll(0, results);
                    return completeResults;
                }
            }
        }
        return completeResults;
    }

    /**
     * Check for BSP compliance
     * @param encAlgo The encryption algorithm
     * @throws WSSecurityException
     */
    private static void checkBSPCompliance(
        String encAlgo, BSPEnforcer bspEnforcer
    ) throws WSSecurityException {
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
