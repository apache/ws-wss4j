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

import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.apache.wss4j.common.ext.Attachment;
import org.apache.wss4j.common.ext.AttachmentRequestCallback;
import org.apache.wss4j.common.ext.AttachmentResultCallback;
import org.apache.wss4j.common.util.AttachmentUtils;
import org.apache.xml.security.algorithms.JCEMapper;
import org.w3c.dom.Attr;
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
import org.apache.wss4j.dom.message.CallbackLookup;
import org.apache.wss4j.dom.message.token.SecurityTokenReference;
import org.apache.wss4j.dom.str.STRParser;
import org.apache.wss4j.dom.str.STRParserParameters;
import org.apache.wss4j.dom.str.STRParserResult;
import org.apache.wss4j.dom.str.SecurityTokenRefSTRParser;
import org.apache.wss4j.dom.util.WSSecurityUtil;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.encryption.XMLEncryptionException;

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
        return Collections.singletonList(result);
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
        List<WSDataRef> dataRefs = new ArrayList<>();
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
                String dataRefURI = ((Element) node).getAttributeNS(null, "URI");
                if (dataRefURI.charAt(0) == '#') {
                    dataRefURI = dataRefURI.substring(1);
                }
                
                // See whether we have already processed the encrypted node 
                if (!wsDocInfo.hasResult(WSConstants.ENCR, dataRefURI)) {
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
        if (LOG.isDebugEnabled()) {
            LOG.debug("Found data reference: " + dataRefURI);
        }
        //
        // Find the encrypted data element referenced by dataRefURI
        //
        Element encryptedDataElement = findEncryptedDataElement(doc, wsDocInfo, dataRefURI);
        
        if (encryptedDataElement != null && asymBinding && data.isRequireSignedEncryptedDataElements()) {
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
            STRParserParameters parameters = new STRParserParameters();
            parameters.setData(data);
            parameters.setWsDocInfo(wsDocInfo);
            parameters.setStrElement(secRefToken);
            if (symEncAlgo != null) {
                parameters.setDerivationKeyLength(KeyUtils.getKeyLength(symEncAlgo));
            }
            
            STRParser strParser = new SecurityTokenRefSTRParser();
            STRParserResult parserResult = strParser.parseSecurityTokenReference(parameters);
            byte[] secretKey = parserResult.getSecretKey();
            principal = parserResult.getPrincipal();
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
            decryptEncryptedData(
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
        Element encryptedDataElement = 
            callbackLookup.getElement(dataRefURI, null, true);
        if (encryptedDataElement == null) {
            throw new WSSecurityException(
                WSSecurityException.ErrorCode.INVALID_SECURITY, "dataRef", dataRefURI);
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
        String symEncAlgo,
        RequestData requestData
    ) throws WSSecurityException {

        WSDataRef dataRef = new WSDataRef();
        dataRef.setWsuId(dataRefURI);
        dataRef.setAlgorithm(symEncAlgo);

        String typeStr = encData.getAttributeNS(null, "Type");
        if (typeStr != null &&
            (WSConstants.SWA_ATTACHMENT_ENCRYPTED_DATA_TYPE_CONTENT_ONLY.equals(typeStr) ||
            WSConstants.SWA_ATTACHMENT_ENCRYPTED_DATA_TYPE_COMPLETE.equals(typeStr))) {

            try {
                Element cipherData = WSSecurityUtil.getDirectChildElement(encData, "CipherData", WSConstants.ENC_NS);
                if (cipherData == null) {
                    throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_CHECK);
                }
                Element cipherReference = WSSecurityUtil.getDirectChildElement(cipherData, "CipherReference", WSConstants.ENC_NS);
                if (cipherReference == null) {
                    throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_CHECK);
                }
                String uri = cipherReference.getAttributeNS(null, "URI");
                if (uri == null || uri.length() < 5) {
                    throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_CHECK);
                }
                if (!uri.startsWith("cid:")) {
                    throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_CHECK);
                }
                dataRef.setWsuId(uri);
                dataRef.setAttachment(true);

                CallbackHandler attachmentCallbackHandler = requestData.getAttachmentCallbackHandler();
                if (attachmentCallbackHandler == null) {
                    throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_CHECK);
                }

                final String attachmentId = uri.substring(4);

                AttachmentRequestCallback attachmentRequestCallback = new AttachmentRequestCallback();
                attachmentRequestCallback.setAttachmentId(attachmentId);

                attachmentCallbackHandler.handle(new Callback[]{attachmentRequestCallback});
                List<Attachment> attachments = attachmentRequestCallback.getAttachments();
                if (attachments == null || attachments.isEmpty() || !attachmentId.equals(attachments.get(0).getId())) {
                    throw new WSSecurityException(
                            WSSecurityException.ErrorCode.INVALID_SECURITY,
                            "empty", "Attachment not found"
                    );
                }
                Attachment attachment = attachments.get(0);

                final String encAlgo = X509Util.getEncAlgo(encData);
                final String jceAlgorithm =
                        JCEMapper.translateURItoJCEID(encAlgo);
                final Cipher cipher = Cipher.getInstance(jceAlgorithm);

                InputStream attachmentInputStream =
                        AttachmentUtils.setupAttachmentDecryptionStream(
                                encAlgo, cipher, symmetricKey, attachment.getSourceStream());

                Attachment resultAttachment = new Attachment();
                resultAttachment.setId(attachment.getId());
                resultAttachment.setMimeType(encData.getAttributeNS(null, "MimeType"));
                resultAttachment.setSourceStream(attachmentInputStream);
                resultAttachment.addHeaders(attachment.getHeaders());

                if (WSConstants.SWA_ATTACHMENT_ENCRYPTED_DATA_TYPE_COMPLETE.equals(typeStr)) {
                    AttachmentUtils.readAndReplaceEncryptedAttachmentHeaders(
                            resultAttachment.getHeaders(), attachmentInputStream);
                }

                AttachmentResultCallback attachmentResultCallback = new AttachmentResultCallback();
                attachmentResultCallback.setAttachment(resultAttachment);
                attachmentResultCallback.setAttachmentId(resultAttachment.getId());
                attachmentCallbackHandler.handle(new Callback[]{attachmentResultCallback});

            } catch (UnsupportedCallbackException | IOException
                | NoSuchAlgorithmException | NoSuchPaddingException e) {
                throw new WSSecurityException(
                        WSSecurityException.ErrorCode.FAILED_CHECK, e);
            }

            dataRef.setContent(true);
            // Remove this EncryptedData from the security header to avoid processing it again
            encData.getParentNode().removeChild(encData);
            
            return dataRef;
        }

        boolean content = X509Util.isContent(encData);
        dataRef.setContent(content);
        
        Node parent = encData.getParentNode();
        Node previousSibling = encData.getPreviousSibling();
        if (content) {
            encData = (Element) encData.getParentNode();
            parent = encData.getParentNode();
        }

        XMLCipher xmlCipher = null;
        try {
            xmlCipher = XMLCipher.getInstance(symEncAlgo);
            xmlCipher.setSecureValidation(true);
            xmlCipher.init(XMLCipher.DECRYPT_MODE, symmetricKey);
        } catch (XMLEncryptionException ex) {
            throw new WSSecurityException(
                    WSSecurityException.ErrorCode.UNSUPPORTED_ALGORITHM, ex
            );
        }
        
        try {
            xmlCipher.doFinal(doc, encData, content);
        } catch (Exception ex) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_CHECK, ex);
        }
        
        if (parent.getLocalName().equals(WSConstants.ENCRYPTED_HEADER)
            && parent.getNamespaceURI().equals(WSConstants.WSSE11_NS)
            || parent.getLocalName().equals(WSConstants.ENCRYPED_ASSERTION_LN)
            && parent.getNamespaceURI().equals(WSConstants.SAML2_NS)) {
                
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
