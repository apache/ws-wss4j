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

package org.apache.wss4j.api.dom.message;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.spec.ExcC14NParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;

import org.apache.wss4j.api.dom.WSEncryptionPart;
import org.apache.wss4j.api.dom.callback.DOMCallbackLookup;
import org.apache.wss4j.api.dom.token.SecurityTokenReference;
import org.apache.wss4j.common.ext.Attachment;
import org.apache.wss4j.common.ext.AttachmentRequestCallback;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.util.AttachmentUtils;
import org.apache.wss4j.common.util.XMLUtils;
import org.apache.wss4j.api.dom.WSConstants;
import org.apache.wss4j.api.dom.WSDocInfo;
import org.apache.wss4j.api.dom.transform.AttachmentTransformParameterSpec;
import org.apache.wss4j.api.dom.transform.STRTransform;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

/**
 * This is the base class for WS Security messages that are used for signature generation or
 * verification.
 */
public class WSSecSignatureBase extends WSSecBase {

    private static final org.slf4j.Logger LOG =
        org.slf4j.LoggerFactory.getLogger(WSSecSignatureBase.class);

    protected KeyInfo keyInfo;
    protected XMLSignatureFactory signatureFactory;
    protected byte[] secretKey;
    protected String strUri;
    protected Element bstToken;
    protected boolean bstAddedToSecurityHeader;
    protected String certUri;
    protected String keyInfoUri;
    protected SecurityTokenReference secRef;
    protected CanonicalizationMethod c14nMethod;
    protected XMLSignature sig;
    protected byte[] signatureValue;
    protected boolean useCustomSecRef;

    private List<Element> clonedElements = new ArrayList<>();
    private String sigAlgo;
    private Element customKeyInfoElement;
    private Provider signatureProvider;
    private String canonAlgo = WSConstants.C14N_EXCL_OMIT_COMMENTS;
    private boolean addInclusivePrefixes = true;
    private String digestAlgo = WSConstants.SHA1;

    public WSSecSignatureBase(WSSecHeader securityHeader) {
        this(securityHeader, null);
    }

    public WSSecSignatureBase(WSSecHeader securityHeader, Provider provider) {
        super(securityHeader);
        init(provider);
    }

    public WSSecSignatureBase(Document doc) {
        this(doc, null);
    }

    public WSSecSignatureBase(Document doc, Provider provider) {
        super(doc);
        init(provider);
    }

    private void init(Provider provider) {
        if (provider == null) {
            // Try to install the Santuario Provider - fall back to the JDK provider if this does
            // not work
            try {
                signatureFactory = XMLSignatureFactory.getInstance("DOM", "ApacheXMLDSig");
            } catch (NoSuchProviderException ex) {
                signatureFactory = XMLSignatureFactory.getInstance("DOM");
            }
        } else {
            signatureFactory = XMLSignatureFactory.getInstance("DOM", provider);
        }
    }

    /**
     * This method adds references to the Signature.
     *
     * @param references The list of references to sign
     * @throws WSSecurityException
     */
    public List<javax.xml.crypto.dsig.Reference> addReferencesToSign(
        List<WSEncryptionPart> references
    ) throws WSSecurityException {
        return
            addReferencesToSign(
                getDocument(),
                references,
                getWsDocInfo(),
                signatureFactory,
                addInclusivePrefixes,
                digestAlgo
            );
    }

    /**
     * This method adds references to the Signature.
     *
     * @param doc The parent document
     * @param references The list of references to sign
     * @param wsDocInfo The WSDocInfo object to store protection elements in
     * @param signatureFactory The XMLSignature object
     * @param addInclusivePrefixes Whether to add inclusive prefixes or not
     * @param digestAlgo The digest algorithm to use
     * @throws WSSecurityException
     */
    public List<javax.xml.crypto.dsig.Reference> addReferencesToSign(
        Document doc,
        List<WSEncryptionPart> references,
        WSDocInfo wsDocInfo,
        XMLSignatureFactory signatureFactory,
        boolean addInclusivePrefixes,
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
        List<javax.xml.crypto.dsig.Reference> attachmentReferenceList = null;
        List<javax.xml.crypto.dsig.Reference> referenceList = new ArrayList<>();

        for (WSEncryptionPart encPart : references) {
            String idToSign = encPart.getId();
            String elemName = encPart.getName();
            Element element = encPart.getElement();

            //
            // Set up the elements to sign. There is one reserved element
            // names: "STRTransform": Setup the ds:Reference to use STR Transform
            //
            try {
                if ("cid:Attachments".equals(idToSign) && attachmentReferenceList == null) {
                    attachmentReferenceList =
                        addAttachmentReferences(encPart, digestMethod, signatureFactory);
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
                        if (addInclusivePrefixes && element != null) {
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
                        cloneElement(element);

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
                        elementsToSign = encPart.findElements(callbackLookup);
                    }
                    if (elementsToSign == null || elementsToSign.isEmpty()) {
                        if (!encPart.isRequired()) {
                            continue;
                        }
                        throw new WSSecurityException(
                            WSSecurityException.ErrorCode.FAILURE,
                            "noEncElement",
                            new Object[] {nmSpace + ", " + elemName});
                    }
                    for (Element elementToSign : elementsToSign) {
                        String wsuId = setWsuId(elementToSign);

                        cloneElement(elementToSign);

                        TransformParameterSpec transformSpec = null;
                        if (addInclusivePrefixes) {
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
                                "#" + wsuId,
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
        if (attachmentReferenceList != null) {
            referenceList.addAll(attachmentReferenceList);
        }
        return referenceList;
    }

    private void cloneElement(Element element) throws WSSecurityException {
        if (expandXopInclude) {
            // Look for xop:Include Nodes
            List<Element> includeElements =
                XMLUtils.findElements(element.getFirstChild(), "Include", WSConstants.XOP_NS);
            if (includeElements != null && !includeElements.isEmpty()) {
                // Clone the Element to be signed + insert the clone into the tree at the same level
                // We will expand the xop:Include for one of the nodes + sign that (and then remove it),
                // while leaving the original in the tree to be sent in the message

                clonedElements.add(element);
                Document doc = this.getSecurityHeader().getSecurityHeaderDoc();
                element.getParentNode().appendChild(XMLUtils.cloneElement(doc, element));
                inlineAttachments(includeElements, attachmentCallbackHandler, false);
            }
        }
    }

    private List<javax.xml.crypto.dsig.Reference> addAttachmentReferences(
        WSEncryptionPart encPart,
        DigestMethod digestMethod,
        XMLSignatureFactory signatureFactory
    ) throws WSSecurityException {

        if (attachmentCallbackHandler == null) {
            throw new WSSecurityException(
                WSSecurityException.ErrorCode.FAILURE,
                "empty", new Object[] {"no attachment callbackhandler supplied"}
            );
        }

        AttachmentRequestCallback attachmentRequestCallback = new AttachmentRequestCallback();
        //no mime type must be set for signature:
        //attachmentCallback.setResultingMimeType(null);
        String id = AttachmentUtils.getAttachmentId(encPart.getId());
        attachmentRequestCallback.setAttachmentId(id);
        try {
            attachmentCallbackHandler.handle(new Callback[]{attachmentRequestCallback});
        } catch (Exception e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, e);
        }

        List<javax.xml.crypto.dsig.Reference> attachmentReferenceList = new ArrayList<>();
        if (attachmentRequestCallback.getAttachments() != null) {
            for (Attachment attachment : attachmentRequestCallback.getAttachments()) {
                try {
                    List<Transform> transforms = new ArrayList<>();

                    AttachmentTransformParameterSpec attachmentTransformParameterSpec =
                        new AttachmentTransformParameterSpec(
                            attachmentCallbackHandler, attachment
                        );

                    String attachmentSignatureTransform = WSConstants.SWA_ATTACHMENT_CONTENT_SIG_TRANS;
                    if ("Element".equals(encPart.getEncModifier())) {
                        attachmentSignatureTransform = WSConstants.SWA_ATTACHMENT_COMPLETE_SIG_TRANS;
                    }

                    transforms.add(
                        signatureFactory.newTransform(
                            attachmentSignatureTransform, attachmentTransformParameterSpec)
                        );

                    javax.xml.crypto.dsig.Reference reference =
                        signatureFactory.newReference(
                            "cid:" + attachment.getId(), digestMethod, transforms, null, null
                        );

                    attachmentReferenceList.add(reference);
                } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException e) {
                    throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, e);
                }
            }
        }

        return attachmentReferenceList;
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
        return SignatureUtils.getInclusivePrefixes(target, excludeVisible);
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

    protected void cleanup() {
        if (!clonedElements.isEmpty()) {
            for (Element clonedElement : clonedElements) {
                clonedElement.getParentNode().removeChild(clonedElement);
            }
            clonedElements.clear();
        }
    }

    private static void inlineAttachments(List<Element> includeElements,
                                         CallbackHandler attachmentCallbackHandler,
                                         boolean removeAttachments) throws WSSecurityException {
        for (Element includeElement : includeElements) {
            String xopURI = includeElement.getAttributeNS(null, "href");
            if (xopURI != null) {
                // Retrieve the attachment bytes
                byte[] attachmentBytes =
                    AttachmentUtils.getBytesFromAttachment(xopURI, attachmentCallbackHandler, removeAttachments);
                String encodedBytes = org.apache.xml.security.utils.XMLUtils.encodeToString(attachmentBytes);

                Node encodedChild =
                    includeElement.getOwnerDocument().createTextNode(encodedBytes);
                includeElement.getParentNode().replaceChild(encodedChild, includeElement);
            }
        }
    }

    /**
     * Set the name (uri) of the signature encryption algorithm to use.
     *
     * If the algorithm is not set then an automatic detection of the signature
     * algorithm to use is performed during the <code>prepare()</code>
     * method. Refer to WSConstants which algorithms are supported.
     *
     * @param algo the name of the signature algorithm
     * @see WSConstants#RSA
     * @see WSConstants#DSA
     */
    public void setSignatureAlgorithm(String algo) {
        sigAlgo = algo;
    }

    /**
     * Get the name (uri) of the signature algorithm that is being used.
     *
     * Call this method after <code>prepare</code> to get the information
     * which signature algorithm was automatically detected if no signature
     * algorithm was preset.
     *
     * @return the identifier URI of the signature algorithm
     */
    public String getSignatureAlgorithm() {
        return sigAlgo;
    }

     /**
     * Prepend the BinarySecurityToken to the elements already in the Security
     * header.
     *
     * The method can be called any time after <code>prepare()</code>.
     * This allows to insert the BST element at any position in the Security
     * header.
     */
    public void prependBSTElementToHeader() {
        if (bstToken != null && !bstAddedToSecurityHeader) {
            Element securityHeaderElement = getSecurityHeader().getSecurityHeaderElement();
            XMLUtils.prependChildElement(securityHeaderElement, bstToken);
            bstAddedToSecurityHeader = true;
        }
    }

    /**
     * Append the BinarySecurityToken to the security header.
     */
    public void appendBSTElementToHeader() {
        if (bstToken != null && !bstAddedToSecurityHeader) {
            Element securityHeaderElement = getSecurityHeader().getSecurityHeaderElement();
            securityHeaderElement.appendChild(bstToken);
            bstAddedToSecurityHeader = true;
        }
    }

    public void setCustomKeyInfoElement(Element keyInfoElement) {
        this.customKeyInfoElement = keyInfoElement;
    }

    public Element getCustomKeyInfoElement() {
        return customKeyInfoElement;
    }

    public Provider getSignatureProvider() {
        return signatureProvider;
    }

    public void setSignatureProvider(Provider signatureProvider) {
        this.signatureProvider = signatureProvider;
    }


    /**
     * Set the canonicalization method to use.
     *
     * If the canonicalization method is not set then the recommended Exclusive
     * XML Canonicalization is used by default. Refer to WSConstants which
     * algorithms are supported.
     *
     * @param algo Is the name of the signature algorithm
     * @see WSConstants#C14N_OMIT_COMMENTS
     * @see WSConstants#C14N_WITH_COMMENTS
     * @see WSConstants#C14N_EXCL_OMIT_COMMENTS
     * @see WSConstants#C14N_EXCL_WITH_COMMENTS
     */
    public void setSigCanonicalization(String algo) {
        canonAlgo = algo;
    }

    /**
     * Get the canonicalization method.
     *
     * If the canonicalization method was not set then Exclusive XML
     * Canonicalization is used by default.
     *
     * @return The string describing the canonicalization algorithm.
     */
    public String getSigCanonicalization() {
        return canonAlgo;
    }

    public boolean isAddInclusivePrefixes() {
        return addInclusivePrefixes;
    }

    public void setAddInclusivePrefixes(boolean addInclusivePrefixes) {
        this.addInclusivePrefixes = addInclusivePrefixes;
    }

    protected void marshalKeyInfo(WSDocInfo wsDocInfo) throws WSSecurityException {
        List<XMLStructure> kiChildren = null;
        if (getCustomKeyInfoElement() == null) {
            XMLStructure structure = new DOMStructure(secRef.getElement());
            wsDocInfo.addTokenElement(secRef.getElement(), false);
            kiChildren = Collections.singletonList(structure);
        } else {
            Node kiChild = getCustomKeyInfoElement().getFirstChild();
            kiChildren = new ArrayList<>();
            while (kiChild != null) {
                kiChildren.add(new DOMStructure(kiChild));
                kiChild = kiChild.getNextSibling();
            }
        }

        KeyInfoFactory keyInfoFactory = signatureFactory.getKeyInfoFactory();
        keyInfo = keyInfoFactory.newKeyInfo(kiChildren, keyInfoUri);
    }

    /**
     * Get the SecurityTokenReference to be used in the KeyInfo element.
     */
    public SecurityTokenReference getSecurityTokenReference() {
        return secRef;
    }

    /**
     * Set the SecurityTokenReference to be used in the KeyInfo element. If this
     * method is not called, a SecurityTokenRefence will be generated.
     */
    public void setSecurityTokenReference(SecurityTokenReference secRef) {
        useCustomSecRef = true;
        this.secRef = secRef;
    }

    /**
     * @return the digest algorithm to use
     */
    public String getDigestAlgo() {
        return digestAlgo;
    }

    /**
     * Set the string that defines which digest algorithm to use.
     * The default is WSConstants.SHA1.
     *
     * @param digestAlgo the digestAlgo to set
     */
    public void setDigestAlgo(String digestAlgo) {
        this.digestAlgo = digestAlgo;
    }

    /**
     * Returns the computed Signature value.
     *
     * Call this method after <code>computeSignature()</code> or <code>build()</code>
     * methods were called.
     *
     * @return Returns the signatureValue.
     */
    public byte[] getSignatureValue() {
        return signatureValue;
    }

    /**
     * Set the secret key to use
     * @param secretKey the secret key to use
     */
    public void setSecretKey(byte[] secretKey) {
        this.secretKey = secretKey;
    }
}
