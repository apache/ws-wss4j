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
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.crypto.SecretKey;

import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSDataRef;
import org.apache.ws.security.WSDerivedKeyTokenPrincipal;
import org.apache.ws.security.WSDocInfo;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.AlgorithmSuite;
import org.apache.ws.security.components.crypto.AlgorithmSuiteValidator;
import org.apache.ws.security.handler.RequestData;
import org.apache.ws.security.message.CallbackLookup;
import org.apache.ws.security.message.DOMCallbackLookup;
import org.apache.ws.security.message.token.SecurityTokenReference;
import org.apache.ws.security.str.STRParser;
import org.apache.ws.security.str.SecurityTokenRefSTRParser;
import org.apache.ws.security.util.WSSecurityUtil;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.encryption.XMLEncryptionException;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

public class ReferenceListProcessor implements Processor {
    private static org.apache.commons.logging.Log log = 
        org.apache.commons.logging.LogFactory.getLog(ReferenceListProcessor.class);
    
    public List<WSSecurityEngineResult> handleToken(
        Element elem, 
        RequestData data, 
        WSDocInfo wsDocInfo 
    ) throws WSSecurityException {
        if (log.isDebugEnabled()) {
            log.debug("Found reference list element");
        }
        List<WSDataRef> dataRefs = handleReferenceList(elem, data, wsDocInfo);
        WSSecurityEngineResult result = 
            new WSSecurityEngineResult(WSConstants.ENCR, dataRefs);
        result.put(WSSecurityEngineResult.TAG_ID, elem.getAttributeNS(null, "Id"));
        wsDocInfo.addTokenElement(elem);
        wsDocInfo.addResult(result);
        return java.util.Collections.singletonList(result);
    }

    /**
     * Dereferences and decodes encrypted data elements.
     * 
     * @param elem contains the <code>ReferenceList</code> to the encrypted
     *             data elements
     * @param cb the callback handler to get the key for a key name stored if
     *           <code>KeyInfo</code> inside the encrypted data elements
     */
    private List<WSDataRef> handleReferenceList(
        Element elem, 
        RequestData data,
        WSDocInfo wsDocInfo
    ) throws WSSecurityException {
        List<WSDataRef> dataRefs = new ArrayList<WSDataRef>();
        //find out if there's an EncryptedKey in the doc (AsymmetricBinding)
        Element wsseHeaderElement = wsDocInfo.getSecurityHeader();
        boolean asymBinding = WSSecurityUtil.getDirectChildElement(
            wsseHeaderElement, WSConstants.ENC_KEY_LN, WSConstants.ENC_NS) != null;
        for (Node node = elem.getFirstChild(); 
            node != null; 
            node = node.getNextSibling()
        ) {
            if (Node.ELEMENT_NODE == node.getNodeType()
                && WSConstants.ENC_NS.equals(node.getNamespaceURI())
                && "DataReference".equals(node.getLocalName())) {
                String dataRefURI = ((Element) node).getAttribute("URI");
                if (dataRefURI.charAt(0) == '#') {
                    dataRefURI = dataRefURI.substring(1);
                }
                
                if (wsDocInfo.getResultByTag(WSConstants.ENCR, dataRefURI) == null) {
                    WSDataRef dataRef = 
                        decryptDataRefEmbedded(
                            elem.getOwnerDocument(), dataRefURI, data, wsDocInfo, asymBinding);
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
        WSDocInfo wsDocInfo,
        boolean asymBinding
    ) throws WSSecurityException {
        if (log.isDebugEnabled()) {
            log.debug("Found data reference: " + dataRefURI);
        }
        //
        // Find the encrypted data element referenced by dataRefURI
        //
        Element encryptedDataElement = findEncryptedDataElement(doc, wsDocInfo, dataRefURI);
        
        if (encryptedDataElement != null && asymBinding && data.isRequireSignedEncryptedDataElements()) {
            WSSecurityUtil.verifySignedElement(encryptedDataElement, doc, wsDocInfo.getSecurityHeader());
        }
        //
        // Prepare the SecretKey object to decrypt EncryptedData
        //
        String symEncAlgo = X509Util.getEncAlgo(encryptedDataElement);
        Element keyInfoElement = 
            (Element)WSSecurityUtil.getDirectChildElement(
                encryptedDataElement, "KeyInfo", WSConstants.SIG_NS
            );
        // KeyInfo cannot be null
        if (keyInfoElement == null) {
            throw new WSSecurityException(WSSecurityException.INVALID_SECURITY, "noKeyinfo");
        }
        // Check BSP compliance
        if (data.getWssConfig().isWsiBSPCompliant()) {
            checkBSPCompliance(keyInfoElement, symEncAlgo);
        }
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
            symmetricKey = WSSecurityUtil.prepareSecretKey(symEncAlgo, secretKey);
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
            decryptEncryptedData(
                doc, dataRefURI, encryptedDataElement, symmetricKey, symEncAlgo
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
        String encAlgo
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
            throw new WSSecurityException(
                WSSecurityException.INVALID_SECURITY, "invalidDataRef"
            );
        }
        
        if (!WSConstants.WSSE_NS.equals(child.getNamespaceURI()) || 
            !SecurityTokenReference.SECURITY_TOKEN_REFERENCE.equals(child.getLocalName())) {
            throw new WSSecurityException(
                WSSecurityException.INVALID_SECURITY, "noSecTokRef"
            );
        }
        
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

    /**
     * Look up the encrypted data. First try Id="someURI". If no such Id then try 
     * wsu:Id="someURI".
     * 
     * @param doc The document in which to find EncryptedData
     * @param wsDocInfo The WSDocInfo object to use
     * @param dataRefURI The URI of EncryptedData
     * @return The EncryptedData element
     * @throws WSSecurityException if the EncryptedData element referenced by dataRefURI is 
     * not found
     */
    public static Element
    findEncryptedDataElement(
        Document doc,
        WSDocInfo wsDocInfo,
        String dataRefURI
    ) throws WSSecurityException {
        CallbackLookup callbackLookup = wsDocInfo.getCallbackLookup();
        if (callbackLookup == null) {
            callbackLookup = new DOMCallbackLookup(doc);
        }
        Element encryptedDataElement = 
            callbackLookup.getElement(dataRefURI, null, true);
        if (encryptedDataElement == null) {
            throw new WSSecurityException(
                WSSecurityException.INVALID_SECURITY, "dataRef", new Object[] {dataRefURI}
            );
        }
        if (encryptedDataElement.getLocalName().equals(WSConstants.ENCRYPTED_HEADER)
            && encryptedDataElement.getNamespaceURI().equals(WSConstants.WSSE11_NS)) {
            Node child = encryptedDataElement.getFirstChild();
            while (child != null && child.getNodeType() != Node.ELEMENT_NODE) {
                child = child.getNextSibling();
            }
            return (Element)child;
        }
        return encryptedDataElement;
    }

    
    /**
     * Decrypt the EncryptedData argument using a SecretKey.
     * @param doc The (document) owner of EncryptedData
     * @param dataRefURI The URI of EncryptedData
     * @param encData The EncryptedData element
     * @param symmetricKey The SecretKey with which to decrypt EncryptedData
     * @param symEncAlgo The symmetric encryption algorithm to use
     * @throws WSSecurityException
     */
    public static WSDataRef
    decryptEncryptedData(
        Document doc,
        String dataRefURI,
        Element encData,
        SecretKey symmetricKey,
        String symEncAlgo
    ) throws WSSecurityException {
        XMLCipher xmlCipher = null;
        try {
            xmlCipher = XMLCipher.getInstance(symEncAlgo);
            xmlCipher.setSecureValidation(true);
            xmlCipher.init(XMLCipher.DECRYPT_MODE, symmetricKey);
        } catch (XMLEncryptionException ex) {
            throw new WSSecurityException(
                WSSecurityException.UNSUPPORTED_ALGORITHM, null, null, ex
            );
        }

        WSDataRef dataRef = new WSDataRef();
        dataRef.setWsuId(dataRefURI);
        dataRef.setAlgorithm(symEncAlgo);
        boolean content = X509Util.isContent(encData);
        dataRef.setContent(content);
        
        Node parent = encData.getParentNode();
        Node previousSibling = encData.getPreviousSibling();
        if (content) {
            encData = (Element) encData.getParentNode();
            parent = encData.getParentNode();
        }
        
        try {
            xmlCipher.doFinal(doc, encData, content);
        } catch (Exception ex) {
            throw new WSSecurityException(WSSecurityException.FAILED_CHECK, null, null, ex);
        }
        
        if (parent.getLocalName().equals(WSConstants.ENCRYPTED_HEADER)
            && parent.getNamespaceURI().equals(WSConstants.WSSE11_NS)) {
                
            Node decryptedHeader = parent.getFirstChild();
            Node soapHeader = parent.getParentNode();
            soapHeader.replaceChild(decryptedHeader, parent);

            dataRef.setProtectedElement((Element)decryptedHeader);
            dataRef.setXpath(getXPath(decryptedHeader));
        } else if (content) {
            dataRef.setProtectedElement(encData);
            dataRef.setXpath(getXPath(encData));
        } else {
            Node decryptedNode;
            if (previousSibling == null) {
                decryptedNode = parent.getFirstChild();
            } else {
                decryptedNode = previousSibling.getNextSibling();
            }
            if (decryptedNode != null && Node.ELEMENT_NODE == decryptedNode.getNodeType()) {
                dataRef.setProtectedElement((Element)decryptedNode);
            }
            dataRef.setXpath(getXPath(decryptedNode));
        }
        
        return dataRef;
    }
    
    
    public String getId() {
        return null;
    }

    
    /**
     * @param decryptedNode the decrypted node
     * @return a fully built xpath 
     *        (eg. &quot;/soapenv:Envelope/soapenv:Body/ns:decryptedElement&quot;)
     *        if the decryptedNode is an Element or an Attr node and is not detached
     *        from the document. <code>null</code> otherwise
     */
    public static String getXPath(Node decryptedNode) {
        if (decryptedNode == null) {
            return null;
        }
        
        String result = "";
        if (Node.ELEMENT_NODE == decryptedNode.getNodeType()) {
            result = decryptedNode.getNodeName();
            result = prependFullPath(result, decryptedNode.getParentNode());
        } else if (Node.ATTRIBUTE_NODE == decryptedNode.getNodeType()) {
            result = "@" + decryptedNode.getNodeName();
            result = prependFullPath(result, ((Attr)decryptedNode).getOwnerElement());
        } else {
            return null;
        }
        
        return result;
    }


    /**
     * Recursively build an absolute xpath (starting with the root &quot;/&quot;)
     * 
     * @param xpath the xpath expression built so far
     * @param node the current node whose name is to be prepended
     * @return a fully built xpath
     */
    private static String prependFullPath(String xpath, Node node) {
        if (node == null) {
            // probably a detached node... not really useful
            return null;
        } else if (Node.ELEMENT_NODE == node.getNodeType()) {
            xpath = node.getNodeName() + "/" + xpath;
            return prependFullPath(xpath, node.getParentNode());
        } else if (Node.DOCUMENT_NODE == node.getNodeType()) {
            return "/" + xpath;
        } else {
            return prependFullPath(xpath, node.getParentNode());
        }
    }

}
