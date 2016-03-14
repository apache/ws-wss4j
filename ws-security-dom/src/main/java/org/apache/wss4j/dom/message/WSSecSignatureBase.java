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

package org.apache.wss4j.dom.message;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.security.auth.callback.Callback;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.spec.ExcC14NParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;

import org.apache.wss4j.common.WSEncryptionPart;
import org.apache.wss4j.common.ext.Attachment;
import org.apache.wss4j.common.ext.AttachmentRequestCallback;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.WSDocInfo;
import org.apache.wss4j.dom.WSSConfig;
import org.apache.wss4j.dom.transform.AttachmentTransformParameterSpec;
import org.apache.wss4j.dom.transform.STRTransform;
import org.apache.wss4j.dom.util.WSSecurityUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;

/**
 * This is the base class for WS Security messages that are used for signature generation or
 * verification.
 */
public class WSSecSignatureBase extends WSSecBase {
    
    private static final org.slf4j.Logger LOG = 
        org.slf4j.LoggerFactory.getLogger(WSSecSignatureBase.class);
    
    public WSSecSignatureBase() {
        super();
    }
    
    public WSSecSignatureBase(WSSConfig config) {
        super(config);
    }
    
    /**
     * This method adds references to the Signature.
     * 
     * @param doc The parent document
     * @param references The list of references to sign
     * @param wsDocInfo The WSDocInfo object to store protection elements in
     * @param signatureFactory The XMLSignature object
     * @param secHeader The Security Header
     * @param addInclusivePrefixes Whether to add inclusive prefixes or not
     * @param digestAlgo The digest algorithm to use
     * @throws WSSecurityException
     */
    public List<javax.xml.crypto.dsig.Reference> addReferencesToSign(
        Document doc,
        List<WSEncryptionPart> references,
        WSDocInfo wsDocInfo,
        XMLSignatureFactory signatureFactory,
        WSSecHeader secHeader,
        WSSConfig wssConfig,
        String digestAlgo
    ) throws WSSecurityException {
        DigestMethod digestMethod;
        try {
            digestMethod = signatureFactory.newDigestMethod(digestAlgo, null);
        } catch (Exception ex) {
            LOG.error("", ex);
            throw new WSSecurityException(
                WSSecurityException.ErrorCode.FAILED_SIGNATURE, ex, "noXMLSig"
            );
        }

        //create separate list for attachment and append it after same document references
        //are processed.
        List<javax.xml.crypto.dsig.Reference> attachmentReferenceList = new ArrayList<javax.xml.crypto.dsig.Reference>();

        for (WSEncryptionPart encPart : references) {
            if (encPart.getId() != null && encPart.getId().startsWith("cid:")) {

                if (attachmentCallbackHandler == null) {
                    throw new WSSecurityException(
                            WSSecurityException.ErrorCode.FAILURE,
                            "empty", new Object[] {"no attachment callbackhandler supplied"}
                    );
                }

                AttachmentRequestCallback attachmentRequestCallback = new AttachmentRequestCallback();
                //no mime type must be set for signature:
                //attachmentCallback.setResultingMimeType(null);
                String id = encPart.getId().substring(4);
                attachmentRequestCallback.setAttachmentId(id);
                try {
                    attachmentCallbackHandler.handle(new Callback[]{attachmentRequestCallback});
                } catch (Exception e) {
                    throw new WSSecurityException(
                            WSSecurityException.ErrorCode.FAILURE, e
                    );
                }
                List<Attachment> attachments = attachmentRequestCallback.getAttachments();
                for (int i = 0; i < attachments.size(); i++) {
                    Attachment attachment = attachments.get(i);

                    try {
                        List<Transform> transforms = new ArrayList<Transform>();

                        AttachmentTransformParameterSpec attachmentTransformParameterSpec =
                                new AttachmentTransformParameterSpec(
                                        attachmentCallbackHandler,
                                        attachment
                                        );

                        String attachmentSignatureTransform;
                        if ("Element".equals(encPart.getEncModifier())) {
                            attachmentSignatureTransform = WSConstants.SWA_ATTACHMENT_COMPLETE_SIG_TRANS;
                        } else {
                            attachmentSignatureTransform = WSConstants.SWA_ATTACHMENT_CONTENT_SIG_TRANS;
                        }

                        transforms.add(
                                signatureFactory.newTransform(
                                        attachmentSignatureTransform,
                                        attachmentTransformParameterSpec)
                        );

                        javax.xml.crypto.dsig.Reference reference =
                                signatureFactory.newReference("cid:" + attachment.getId(),
                                        digestMethod,
                                        transforms,
                                        null,
                                        null
                                );

                        attachmentReferenceList.add(reference);
                    } catch (InvalidAlgorithmParameterException e) {
                        throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, e);
                    } catch (NoSuchAlgorithmException e) {
                        throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, e);
                    }
                }
                break;
            }
        }

        List<javax.xml.crypto.dsig.Reference> referenceList = new ArrayList<javax.xml.crypto.dsig.Reference>();

        for (WSEncryptionPart encPart : references) {
            String idToSign = encPart.getId();
            String elemName = encPart.getName();
            Element element = encPart.getElement();

            //
            // Set up the elements to sign. There is one reserved element
            // names: "STRTransform": Setup the ds:Reference to use STR Transform
            //
            try {
                //attachments are already processed in the above loop
                if ("cid:Attachments".equals(idToSign)) {
                    continue;
                }
                if (idToSign != null) {
                    Transform transform = null;
                    if ("STRTransform".equals(elemName)) {
                        Element ctx = createSTRParameter(doc);
                        
                        XMLStructure structure = new DOMStructure(ctx);
                        transform =
                            signatureFactory.newTransform(
                                STRTransform.TRANSFORM_URI,
                                structure
                            );
                    } else {
                        TransformParameterSpec transformSpec = null;
                        if (element == null) {
                            if (callbackLookup == null) {
                                callbackLookup = new DOMCallbackLookup(doc);
                            }
                            element = callbackLookup.getElement(idToSign, null, false);
                        }
                        if (wssConfig.isAddInclusivePrefixes()) {
                            List<String> prefixes = getInclusivePrefixes(element);
                            if (!prefixes.isEmpty()) {
                                transformSpec = new ExcC14NParameterSpec(prefixes);
                            }
                        }
                        transform =
                            signatureFactory.newTransform(
                                WSConstants.C14N_EXCL_OMIT_COMMENTS,
                                transformSpec
                            );
                    }
                    if (element != null) {
                        wsDocInfo.addTokenElement(element, false);
                    } else if (!encPart.isRequired()) {
                        continue;
                    }
                    javax.xml.crypto.dsig.Reference reference = 
                        signatureFactory.newReference(
                            "#" + idToSign, 
                            digestMethod,
                            Collections.singletonList(transform),
                            null,
                            null
                        );
                    referenceList.add(reference);
                } else {
                    String nmSpace = encPart.getNamespace();
                    List<Element> elementsToSign = null;
                    if (element != null) {
                        elementsToSign = Collections.singletonList(element);
                    } else {
                        if (callbackLookup == null) {
                            callbackLookup = new DOMCallbackLookup(doc);
                        }
                        elementsToSign = 
                            WSSecurityUtil.findElements(encPart, callbackLookup, doc);
                    }
                    if (elementsToSign == null || elementsToSign.size() == 0) {
                        if (!encPart.isRequired()) {
                            continue;
                        }
                        throw new WSSecurityException(
                            WSSecurityException.ErrorCode.FAILURE, 
                            "noEncElement",
                            new Object[] {nmSpace + ", " + elemName});
                    }
                    for (Element elementToSign : elementsToSign) {
                        TransformParameterSpec transformSpec = null;
                        if (wssConfig.isAddInclusivePrefixes()) {
                            List<String> prefixes = getInclusivePrefixes(elementToSign);
                            if (!prefixes.isEmpty()) {
                                transformSpec = new ExcC14NParameterSpec(prefixes);
                            }
                        }
                        Transform transform =
                            signatureFactory.newTransform(
                                WSConstants.C14N_EXCL_OMIT_COMMENTS,
                                transformSpec
                            );
                        javax.xml.crypto.dsig.Reference reference = 
                            signatureFactory.newReference(
                                "#" + setWsuId(elementToSign), 
                                digestMethod,
                                Collections.singletonList(transform),
                                null,
                                null
                            );
                        referenceList.add(reference);
                        wsDocInfo.addTokenElement(elementToSign, false);
                    }
                }
            } catch (Exception ex) {
                LOG.error("", ex);
                throw new WSSecurityException(
                    WSSecurityException.ErrorCode.FAILED_SIGNATURE, ex, "noXMLSig"
                );
            }
        }
        //append attachment references now
        referenceList.addAll(attachmentReferenceList);
        return referenceList;
    }
    
    /**
     * Get the List of inclusive prefixes from the DOM Element argument 
     */
    public List<String> getInclusivePrefixes(Element target) {
        return getInclusivePrefixes(target, true);
    }
    
    
    /**
     * Get the List of inclusive prefixes from the DOM Element argument 
     */
    public List<String> getInclusivePrefixes(Element target, boolean excludeVisible) {
        List<String> result = new ArrayList<String>();
        Node parent = target;
        while (parent.getParentNode() != null &&
            !(Node.DOCUMENT_NODE == parent.getParentNode().getNodeType())) {
            parent = parent.getParentNode();
            NamedNodeMap attributes = parent.getAttributes();
            for (int i = 0; i < attributes.getLength(); i++) {
                Node attribute = attributes.item(i);
                if (WSConstants.XMLNS_NS.equals(attribute.getNamespaceURI())) {
                    if ("xmlns".equals(attribute.getNodeName())) {
                        result.add("#default");
                    } else {
                        result.add(attribute.getLocalName());
                    }
                }
            }
        }

        if (excludeVisible) {
            NamedNodeMap attributes = target.getAttributes();
            for (int i = 0; i < attributes.getLength(); i++) {
                Node attribute = attributes.item(i);
                if (WSConstants.XMLNS_NS.equals(attribute.getNamespaceURI())) {
                    if ("xmlns".equals(attribute.getNodeName())) {
                        result.remove("#default");
                    } else {
                        result.remove(attribute.getLocalName());
                    }
                }
                if (attribute.getPrefix() != null) {
                    result.remove(attribute.getPrefix());
                }
            }

            if (target.getPrefix() == null) {
                result.remove("#default");
            } else {
                result.remove(target.getPrefix());
            }
        }

        return result;
    }
    
    /**
     * Create an STRTransformationParameters element
     */
    public Element createSTRParameter(Document doc) {
        Element transformParam = 
            doc.createElementNS(
                WSConstants.WSSE_NS,
                WSConstants.WSSE_PREFIX + ":TransformationParameters"
            );

        Element canonElem = 
            doc.createElementNS(
                WSConstants.SIG_NS,
                WSConstants.SIG_PREFIX + ":CanonicalizationMethod"
            );

        canonElem.setAttributeNS(null, "Algorithm", WSConstants.C14N_EXCL_OMIT_COMMENTS);
        transformParam.appendChild(canonElem);
        return transformParam;
    }
    
}
