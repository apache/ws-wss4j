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

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.spec.MGF1ParameterSpec;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.Text;
import org.apache.wss4j.common.bsp.BSPRule;
import org.apache.wss4j.common.crypto.AlgorithmSuite;
import org.apache.wss4j.common.crypto.AlgorithmSuiteValidator;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.util.KeyUtils;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.WSDataRef;
import org.apache.wss4j.dom.WSDocInfo;
import org.apache.wss4j.dom.WSSecurityEngineResult;
import org.apache.wss4j.dom.bsp.BSPEnforcer;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.str.EncryptedKeySTRParser;
import org.apache.wss4j.dom.str.STRParser;
import org.apache.wss4j.dom.util.WSSecurityUtil;
import org.apache.xml.security.algorithms.JCEMapper;
import org.apache.xml.security.exceptions.Base64DecodingException;
import org.apache.xml.security.utils.Base64;

public class EncryptedKeyProcessor implements Processor {
    private static final org.slf4j.Logger LOG = 
        org.slf4j.LoggerFactory.getLogger(EncryptedKeyProcessor.class);
    
    public List<WSSecurityEngineResult> handleToken(
        Element elem, 
        RequestData data,
        WSDocInfo wsDocInfo
    ) throws WSSecurityException {
        return handleToken(elem, data, wsDocInfo, data.getAlgorithmSuite());
    }
    
    public List<WSSecurityEngineResult> handleToken(
        Element elem, 
        RequestData data,
        WSDocInfo wsDocInfo,
        AlgorithmSuite algorithmSuite
    ) throws WSSecurityException {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Found encrypted key element");
        }
        
        // See if this key has already been processed. If so then just return the result
        String id = elem.getAttributeNS(null, "Id");
        if (!"".equals(id)) {
             WSSecurityEngineResult result = wsDocInfo.getResult(id);
             if (result != null && 
                 WSConstants.ENCR == (Integer)result.get(WSSecurityEngineResult.TAG_ACTION)
             ) {
                 return java.util.Collections.singletonList(result);
             }
        }
        
        if (data.getDecCrypto() == null) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "noDecCryptoFile");
        }
        if (data.getCallbackHandler() == null) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "noCallback");
        }
        //
        // lookup xenc:EncryptionMethod, get the Algorithm attribute to determine
        // how the key was encrypted. Then check if we support the algorithm
        //
        String encryptedKeyTransportMethod = X509Util.getEncAlgo(elem);
        if (encryptedKeyTransportMethod == null) {
            throw new WSSecurityException(
                WSSecurityException.ErrorCode.UNSUPPORTED_ALGORITHM, "noEncAlgo"
            );
        }
        if (WSConstants.KEYTRANSPORT_RSA15.equals(encryptedKeyTransportMethod)
            && !data.isAllowRSA15KeyTransportAlgorithm()
            && !algorithmSuite.getKeyWrapAlgorithms().contains(WSConstants.KEYTRANSPORT_RSA15)) {
            LOG.debug(
                "The Key transport method does not match the requirement"
            );
            throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY);
        }
            
        // Check BSP Compliance
        checkBSPCompliance(elem, encryptedKeyTransportMethod, data.getBSPEnforcer());
        
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
            throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY, "noCipher");
        }
        
        STRParser strParser = new EncryptedKeySTRParser();
        X509Certificate[] certs = 
            getCertificatesFromEncryptedKey(elem, data, wsDocInfo, strParser);

        // Check for compliance against the defined AlgorithmSuite
        if (algorithmSuite != null) {
            AlgorithmSuiteValidator algorithmSuiteValidator = new
                AlgorithmSuiteValidator(algorithmSuite);

            algorithmSuiteValidator.checkAsymmetricKeyLength(certs[0]);
            algorithmSuiteValidator.checkEncryptionKeyWrapAlgorithm(
                encryptedKeyTransportMethod
            );
        }
        
        try {
            PrivateKey privateKey = data.getDecCrypto().getPrivateKey(certs[0], data.getCallbackHandler());
            OAEPParameterSpec oaepParameterSpec = null;
            if (WSConstants.KEYTRANSPORT_RSAOEP.equals(encryptedKeyTransportMethod)
                    || WSConstants.KEYTRANSPORT_RSAOEP_XENC11.equals(encryptedKeyTransportMethod)) {
                // Get the DigestMethod if it exists
                String digestAlgorithm = getDigestAlgorithm(elem);
                String jceDigestAlgorithm = "SHA-1";
                if (digestAlgorithm != null && !"".equals(digestAlgorithm)) {
                    jceDigestAlgorithm = JCEMapper.translateURItoJCEID(digestAlgorithm);
                }

                String mgfAlgorithm = getMGFAlgorithm(elem);
                MGF1ParameterSpec mgfParameterSpec = new MGF1ParameterSpec("SHA-1");
                if (mgfAlgorithm != null) {
                    if (WSConstants.MGF_SHA224.equals(mgfAlgorithm)) {
                        mgfParameterSpec = new MGF1ParameterSpec("SHA-224");
                    } else if (WSConstants.MGF_SHA256.equals(mgfAlgorithm)) {
                        mgfParameterSpec = new MGF1ParameterSpec("SHA-256");
                    } else if (WSConstants.MGF_SHA384.equals(mgfAlgorithm)) {
                        mgfParameterSpec = new MGF1ParameterSpec("SHA-384");
                    } else if (WSConstants.MGF_SHA512.equals(mgfAlgorithm)) {
                        mgfParameterSpec = new MGF1ParameterSpec("SHA-512");
                    }
                }

                PSource.PSpecified pSource = PSource.PSpecified.DEFAULT;
                byte[] pSourceBytes = getPSource(elem);
                if (pSourceBytes != null) {
                    pSource = new PSource.PSpecified(pSourceBytes);
                }
                
                oaepParameterSpec = 
                    new OAEPParameterSpec(
                        jceDigestAlgorithm, "MGF1", mgfParameterSpec, pSource
                    );
            }
            if (oaepParameterSpec == null) {
                cipher.init(Cipher.UNWRAP_MODE, privateKey);
            } else {
                cipher.init(Cipher.UNWRAP_MODE, privateKey, oaepParameterSpec);
            }
        } catch (Exception ex) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_CHECK, ex);
        }
        
        List<String> dataRefURIs = getDataRefURIs(elem);
        
        byte[] encryptedEphemeralKey = null;
        byte[] decryptedBytes = null;
        try {
            encryptedEphemeralKey = getDecodedBase64EncodedData(xencCipherValue);
            String keyAlgorithm = JCEMapper.translateURItoJCEID(encryptedKeyTransportMethod);
            decryptedBytes = cipher.unwrap(encryptedEphemeralKey, keyAlgorithm, Cipher.SECRET_KEY).getEncoded();
        } catch (IllegalStateException ex) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_CHECK, ex);
        } catch (Exception ex) {
            decryptedBytes = getRandomKey(dataRefURIs, elem.getOwnerDocument(), wsDocInfo);
        }

        List<WSDataRef> dataRefs = decryptDataRefs(dataRefURIs, elem.getOwnerDocument(), wsDocInfo,
            decryptedBytes, data);
        
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
        result.put(WSSecurityEngineResult.TAG_ID, elem.getAttributeNS(null, "Id"));
        result.put(WSSecurityEngineResult.TAG_X509_REFERENCE_TYPE, strParser.getCertificatesReferenceType());
        wsDocInfo.addResult(result);
        wsDocInfo.addTokenElement(elem);
        return java.util.Collections.singletonList(result);
    }
    
    /**
     * Generates a random secret key using the algorithm specified in the
     * first DataReference URI
     * 
     * @param dataRefURIs
     * @param doc
     * @param wsDocInfo
     * @return
     * @throws WSSecurityException
     */
    private static byte[] getRandomKey(List<String> dataRefURIs, Document doc, WSDocInfo wsDocInfo) throws WSSecurityException {
        try {
            String alg = "AES";
            int size = 128;
            if (!dataRefURIs.isEmpty()) {
                String uri = dataRefURIs.iterator().next();
                Element ee = ReferenceListProcessor.findEncryptedDataElement(doc, wsDocInfo, uri);
                String algorithmURI = X509Util.getEncAlgo(ee);
                alg = JCEMapper.getJCEKeyAlgorithmFromURI(algorithmURI);
                size = KeyUtils.getKeyLength(algorithmURI);
            }
            KeyGenerator kgen = KeyGenerator.getInstance(alg);
            kgen.init(size * 8);
            SecretKey k = kgen.generateKey();
            return k.getEncoded();
        } catch (Exception ex) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_CHECK, ex);
        }
    }
    
    /**
     * Method getDecodedBase64EncodedData
     *
     * @param element
     * @return a byte array containing the decoded data
     * @throws WSSecurityException
     */
    private static byte[] getDecodedBase64EncodedData(Element element) throws WSSecurityException {
        StringBuilder sb = new StringBuilder();
        Node node = element.getFirstChild();
        while (node != null) {
            if (Node.TEXT_NODE == node.getNodeType()) {
                sb.append(((Text) node).getData());
            }
            node = node.getNextSibling();
        }
        String encodedData = sb.toString();
        try {
            return Base64.decode(encodedData);
        } catch (Base64DecodingException e) {
            throw new WSSecurityException(
                WSSecurityException.ErrorCode.FAILURE, "decoding.general", e
            );
        }
    }
    
    private static String getDigestAlgorithm(Node encBodyData) throws WSSecurityException {
        Element tmpE = 
            WSSecurityUtil.getDirectChildElement(
                encBodyData, "EncryptionMethod", WSConstants.ENC_NS
            );
        if (tmpE != null) {
            Element digestElement = 
                WSSecurityUtil.getDirectChildElement(tmpE, "DigestMethod", WSConstants.SIG_NS);
            if (digestElement != null) {
                return digestElement.getAttributeNS(null, "Algorithm");
            }
        }
        return null;
    }

    private static String getMGFAlgorithm(Node encBodyData) throws WSSecurityException {
        Element tmpE =
                WSSecurityUtil.getDirectChildElement(
                        encBodyData, "EncryptionMethod", WSConstants.ENC_NS
                );
        if (tmpE != null) {
            Element mgfElement =
                    WSSecurityUtil.getDirectChildElement(tmpE, "MGF", WSConstants.ENC11_NS);
            if (mgfElement != null) {
                return mgfElement.getAttributeNS(null, "Algorithm");
            }
        }
        return null;
    }

    private static byte[] getPSource(Node encBodyData) throws WSSecurityException {
        Element tmpE =
                WSSecurityUtil.getDirectChildElement(
                        encBodyData, "EncryptionMethod", WSConstants.ENC_NS
                );
        if (tmpE != null) {
            Element pSourceElement =
                    WSSecurityUtil.getDirectChildElement(tmpE, "OAEPparams", WSConstants.ENC_NS);
            if (pSourceElement != null) {
                return getDecodedBase64EncodedData(pSourceElement);
            }
        }
        return null;
    }
    
    /**
     * @return the Certificate(s) corresponding to the public key reference in the 
     * EncryptedKey Element
     */
    private X509Certificate[] getCertificatesFromEncryptedKey(
        Element xencEncryptedKey,
        RequestData data,
        WSDocInfo wsDocInfo,
        STRParser strParser
    ) throws WSSecurityException {
        Element keyInfo = 
            WSSecurityUtil.getDirectChildElement(
                xencEncryptedKey, "KeyInfo", WSConstants.SIG_NS
            );
        if (keyInfo != null) {
            Element strElement = null;

            int result = 0;
            Node node = keyInfo.getFirstChild();
            while (node != null) {
                if (Node.ELEMENT_NODE == node.getNodeType()) {
                    result++;
                    strElement = (Element)node;
                }
                node = node.getNextSibling();
            }
            if (result != 1) {
                data.getBSPEnforcer().handleBSPRule(BSPRule.R5424);
            }

            if (strElement == null || strParser == null) {
                throw new WSSecurityException(
                    WSSecurityException.ErrorCode.INVALID_SECURITY, "noSecTokRef"
                );
            }
            strParser.parseSecurityTokenReference(strElement, data, wsDocInfo, null);
            
            X509Certificate[] certs = strParser.getCertificates();
            if (certs == null || certs.length < 1 || certs[0] == null) {
                throw new WSSecurityException(
                    WSSecurityException.ErrorCode.FAILURE,
                    "noCertsFound", "decryption (KeyId)");
            }
            return certs;
        } else {
            throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY, "noKeyinfo");
        }
    }
    
    /**
     * Find the list of all URIs that this encrypted Key references
     */
    private List<String> getDataRefURIs(Element xencEncryptedKey) {
        // Lookup the references that are encrypted with this key
        Element refList = 
            WSSecurityUtil.getDirectChildElement(
                xencEncryptedKey, "ReferenceList", WSConstants.ENC_NS
            );
        List<String> dataRefURIs = new LinkedList<String>();
        if (refList != null) {
            for (Node node = refList.getFirstChild(); node != null; node = node.getNextSibling()) {
                if (Node.ELEMENT_NODE == node.getNodeType()
                        && WSConstants.ENC_NS.equals(node.getNamespaceURI())
                        && "DataReference".equals(node.getLocalName())) {
                    String dataRefURI = ((Element) node).getAttributeNS(null, "URI");
                    if (dataRefURI.charAt(0) == '#') {
                        dataRefURI = dataRefURI.substring(1);
                    }
                    dataRefURIs.add(dataRefURI);
                }
            }
        }
        return dataRefURIs;
    }
    
    /**
     * Decrypt all data references
     */
    private List<WSDataRef> decryptDataRefs(List<String> dataRefURIs, Document doc,
        WSDocInfo docInfo, byte[] decryptedBytes, RequestData data
    ) throws WSSecurityException {
        //
        // At this point we have the decrypted session (symmetric) key. According
        // to W3C XML-Enc this key is used to decrypt _any_ references contained in
        // the reference list
        if (dataRefURIs == null || dataRefURIs.isEmpty()) {
            return null;
        }
        List<WSDataRef> dataRefs = new ArrayList<WSDataRef>();
        for (String dataRefURI : dataRefURIs) {
            WSDataRef dataRef = 
                decryptDataRef(doc, dataRefURI, docInfo, decryptedBytes, data);
            dataRefs.add(dataRef);
        }
        return dataRefs;
    }

    /**
     * Decrypt an EncryptedData element referenced by dataRefURI
     */
    private WSDataRef decryptDataRef(
        Document doc, 
        String dataRefURI, 
        WSDocInfo docInfo,
        byte[] decryptedData,
        RequestData data
    ) throws WSSecurityException {
        if (LOG.isDebugEnabled()) {
            LOG.debug("found data reference: " + dataRefURI);
        }
        //
        // Find the encrypted data element referenced by dataRefURI
        //
        Element encryptedDataElement = 
            ReferenceListProcessor.findEncryptedDataElement(doc, docInfo, dataRefURI);
        if (encryptedDataElement != null && data.isRequireSignedEncryptedDataElements()) {
            WSSecurityUtil.verifySignedElement(encryptedDataElement, doc, docInfo.getSecurityHeader());
        }
        //
        // Prepare the SecretKey object to decrypt EncryptedData
        //
        String symEncAlgo = X509Util.getEncAlgo(encryptedDataElement);
        
        // EncryptionAlgorithm cannot be null
        if (symEncAlgo == null) {
            data.getBSPEnforcer().handleBSPRule(BSPRule.R5601);
        }
        // EncryptionAlgorithm must be 3DES, or AES128, or AES256
        if (!WSConstants.TRIPLE_DES.equals(symEncAlgo)
            && !WSConstants.AES_128.equals(symEncAlgo)
            && !WSConstants.AES_128_GCM.equals(symEncAlgo)
            && !WSConstants.AES_256.equals(symEncAlgo)
            && !WSConstants.AES_256_GCM.equals(symEncAlgo)) {
            data.getBSPEnforcer().handleBSPRule(BSPRule.R5620);
        }
        
        SecretKey symmetricKey = null;
        try {
            symmetricKey = KeyUtils.prepareSecretKey(symEncAlgo, decryptedData);
        } catch (IllegalArgumentException ex) {
            throw new WSSecurityException(
                WSSecurityException.ErrorCode.UNSUPPORTED_ALGORITHM, "badEncAlgo", 
                ex, symEncAlgo);
        }
        
        // Check for compliance against the defined AlgorithmSuite
        AlgorithmSuite algorithmSuite = data.getAlgorithmSuite();
        if (algorithmSuite != null) {
            AlgorithmSuiteValidator algorithmSuiteValidator = new
                AlgorithmSuiteValidator(algorithmSuite);

            algorithmSuiteValidator.checkSymmetricKeyLength(symmetricKey.getEncoded().length);
            algorithmSuiteValidator.checkSymmetricEncryptionAlgorithm(symEncAlgo);
        }

        return ReferenceListProcessor.decryptEncryptedData(
            doc, dataRefURI, encryptedDataElement, symmetricKey, symEncAlgo, data
        );
    }
    
    /**
     * A method to check that the EncryptedKey is compliant with the BSP spec.
     * @throws WSSecurityException
     */
    private void checkBSPCompliance(
        Element elem, String encAlgo, BSPEnforcer bspEnforcer
    ) throws WSSecurityException {
        String attribute = elem.getAttributeNS(null, "Type");
        if (attribute != null && !"".equals(attribute)) {
            bspEnforcer.handleBSPRule(BSPRule.R3209);
        }
        attribute = elem.getAttributeNS(null, "MimeType");
        if (attribute != null && !"".equals(attribute)) {
            bspEnforcer.handleBSPRule(BSPRule.R5622);
        }
        attribute = elem.getAttributeNS(null, "Encoding");
        if (attribute != null && !"".equals(attribute)) {
            bspEnforcer.handleBSPRule(BSPRule.R5623);
        }
        attribute = elem.getAttributeNS(null, "Recipient");
        if (attribute != null && !"".equals(attribute)) {
            bspEnforcer.handleBSPRule(BSPRule.R5602);
        }
        
        // EncryptionAlgorithm must be RSA15, or RSAOEP.
        if (!WSConstants.KEYTRANSPORT_RSA15.equals(encAlgo)
            && !WSConstants.KEYTRANSPORT_RSAOEP.equals(encAlgo)) {
            bspEnforcer.handleBSPRule(BSPRule.R5621);
        }
    }
  
}
