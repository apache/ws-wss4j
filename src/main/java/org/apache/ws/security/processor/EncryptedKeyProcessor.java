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

import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSDataRef;
import org.apache.ws.security.WSDocInfo;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.AlgorithmSuite;
import org.apache.ws.security.components.crypto.AlgorithmSuiteValidator;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoType;
import org.apache.ws.security.handler.RequestData;
import org.apache.ws.security.message.token.SecurityTokenReference;
import org.apache.ws.security.str.EncryptedKeySTRParser;
import org.apache.ws.security.str.STRParser;
import org.apache.ws.security.util.Base64;
import org.apache.ws.security.util.WSSecurityUtil;
import org.apache.xml.security.algorithms.JCEMapper;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.Text;

public class EncryptedKeyProcessor implements Processor {
    private static org.apache.commons.logging.Log log = 
        org.apache.commons.logging.LogFactory.getLog(EncryptedKeyProcessor.class);
    
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
        if (log.isDebugEnabled()) {
            log.debug("Found encrypted key element");
        }
        if (data.getDecCrypto() == null) {
            throw new WSSecurityException(WSSecurityException.FAILURE, "noDecCryptoFile");
        }
        if (data.getCallbackHandler() == null) {
            throw new WSSecurityException(WSSecurityException.FAILURE, "noCallback");
        }
        //
        // lookup xenc:EncryptionMethod, get the Algorithm attribute to determine
        // how the key was encrypted. Then check if we support the algorithm
        //
        String encryptedKeyTransportMethod = X509Util.getEncAlgo(elem);
        if (encryptedKeyTransportMethod == null) {
            throw new WSSecurityException(
                WSSecurityException.UNSUPPORTED_ALGORITHM, "noEncAlgo"
            );
        }
        if (data.getWssConfig().isWsiBSPCompliant()) {
            checkBSPCompliance(elem, encryptedKeyTransportMethod);
        }
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
            throw new WSSecurityException(WSSecurityException.INVALID_SECURITY, "noCipher");
        }
        
        STRParser strParser = new EncryptedKeySTRParser();
        X509Certificate[] certs = 
            getCertificatesFromEncryptedKey(elem, data, data.getDecCrypto(), wsDocInfo, strParser);

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
            if (WSConstants.KEYTRANSPORT_RSAOEP.equals(encryptedKeyTransportMethod)) {
                // Get the DigestMethod if it exists
                String digestAlgorithm = getDigestAlgorithm(elem);
                String jceDigestAlgorithm = "SHA-1";
                if (digestAlgorithm != null && !"".equals(digestAlgorithm)) {
                    jceDigestAlgorithm = JCEMapper.translateURItoJCEID(digestAlgorithm);
                }
                
                oaepParameterSpec = 
                    new OAEPParameterSpec(
                        jceDigestAlgorithm, "MGF1", new MGF1ParameterSpec("SHA-1"), PSource.PSpecified.DEFAULT
                    );
            }
            if (oaepParameterSpec == null) {
                cipher.init(Cipher.DECRYPT_MODE, privateKey);
            } else {
                cipher.init(Cipher.DECRYPT_MODE, privateKey, oaepParameterSpec);
            }
        } catch (Exception ex) {
            throw new WSSecurityException(WSSecurityException.FAILED_CHECK, null, null, ex);
        }
        
        List<String> dataRefURIs = getDataRefURIs(elem);
        
        byte[] encryptedEphemeralKey = null;
        byte[] decryptedBytes = null;
        try {
            encryptedEphemeralKey = getDecodedBase64EncodedData(xencCipherValue);
            decryptedBytes = cipher.doFinal(encryptedEphemeralKey);
        } catch (IllegalStateException ex) {
            throw new WSSecurityException(WSSecurityException.FAILED_CHECK, null, null, ex);
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
                size = WSSecurityUtil.getKeyLength(algorithmURI);
            }
            KeyGenerator kgen = KeyGenerator.getInstance(alg);
            kgen.init(size * 8);
            SecretKey k = kgen.generateKey();
            return k.getEncoded();
        } catch (Exception ex) {
            throw new WSSecurityException(WSSecurityException.FAILED_CHECK, null, null, ex);
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
        return Base64.decode(encodedData);
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
                return digestElement.getAttribute("Algorithm");
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
        Crypto crypto,
        WSDocInfo wsDocInfo,
        STRParser strParser
    ) throws WSSecurityException {
        Element keyInfo = 
            WSSecurityUtil.getDirectChildElement(
                xencEncryptedKey, "KeyInfo", WSConstants.SIG_NS
            );
        if (keyInfo != null) {
            Element strElement = null;
            if (data.getWssConfig().isWsiBSPCompliant()) {
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
                    throw new WSSecurityException(
                        WSSecurityException.INVALID_SECURITY, "invalidDataRef"
                    );
                }
            } else {
                 strElement = 
                    WSSecurityUtil.getDirectChildElement(
                        keyInfo,
                        SecurityTokenReference.SECURITY_TOKEN_REFERENCE,
                        WSConstants.WSSE_NS
                    );
            }
            if (strElement == null || strParser == null) {
                throw new WSSecurityException(
                    WSSecurityException.INVALID_SECURITY, "noSecTokRef"
                );
            }
            strParser.parseSecurityTokenReference(strElement, data, wsDocInfo, null);
            
            X509Certificate[] certs = strParser.getCertificates();
            if (certs == null || certs.length < 1 || certs[0] == null) {
                throw new WSSecurityException(
                    WSSecurityException.FAILURE,
                    "noCertsFound", 
                    new Object[] {"decryption (KeyId)"}
                );
            }
            return certs;
        } else if (!data.getWssConfig().isWsiBSPCompliant() 
            && crypto.getDefaultX509Identifier() != null) {
            String alias = crypto.getDefaultX509Identifier();
            CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
            cryptoType.setAlias(alias);
            X509Certificate[] certs = crypto.getX509Certificates(cryptoType);
            if (certs == null || certs.length < 1 || certs[0] == null) {
                throw new WSSecurityException(
                    WSSecurityException.FAILURE,
                    "noCertsFound", 
                    new Object[] {"decryption (KeyId)"}
                );
            }
            return certs;
        } else {
            throw new WSSecurityException(WSSecurityException.INVALID_SECURITY, "noKeyinfo");
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
                    String dataRefURI = ((Element) node).getAttribute("URI");
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
        if (log.isDebugEnabled()) {
            log.debug("found data reference: " + dataRefURI);
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
        SecretKey symmetricKey = null;
        try {
            symmetricKey = WSSecurityUtil.prepareSecretKey(symEncAlgo, decryptedData);
        } catch (IllegalArgumentException ex) {
            throw new WSSecurityException(
                WSSecurityException.UNSUPPORTED_ALGORITHM, "badEncAlgo", 
                new Object[]{symEncAlgo}, ex
            );
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
            doc, dataRefURI, encryptedDataElement, symmetricKey, symEncAlgo
        );
    }
    
    /**
     * A method to check that the EncryptedKey is compliant with the BSP spec.
     * @throws WSSecurityException
     */
    private void checkBSPCompliance(Element elem, String encAlgo) throws WSSecurityException {
        String attribute = elem.getAttribute("Type");
        if (attribute != null && !"".equals(attribute)) {
            throw new WSSecurityException(
                WSSecurityException.FAILED_CHECK, "badAttribute", new Object[]{attribute}
            );
        }
        attribute = elem.getAttribute("MimeType");
        if (attribute != null && !"".equals(attribute)) {
            throw new WSSecurityException(
                WSSecurityException.FAILED_CHECK, "badAttribute", new Object[]{attribute}
            );
        }
        attribute = elem.getAttribute("Encoding");
        if (attribute != null && !"".equals(attribute)) {
            throw new WSSecurityException(
                WSSecurityException.FAILED_CHECK, "badAttribute", new Object[]{attribute}
            );
        }
        attribute = elem.getAttribute("Recipient");
        if (attribute != null && !"".equals(attribute)) {
            throw new WSSecurityException(
                WSSecurityException.FAILED_CHECK, "badAttribute", new Object[]{attribute}
            );
        }
        
        // EncryptionAlgorithm must be RSA15, or RSAOEP.
        if (!WSConstants.KEYTRANSPORT_RSA15.equals(encAlgo)
            && !WSConstants.KEYTRANSPORT_RSAOEP.equals(encAlgo)) {
            throw new WSSecurityException(
                WSSecurityException.INVALID_SECURITY, "badEncAlgo", new Object[]{encAlgo}
            );
        }
    }
  
}
