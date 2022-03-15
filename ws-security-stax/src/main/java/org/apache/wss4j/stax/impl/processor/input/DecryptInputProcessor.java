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
package org.apache.wss4j.stax.impl.processor.input;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.security.Key;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import javax.crypto.Cipher;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import jakarta.xml.bind.JAXBElement;
import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;

import org.apache.wss4j.binding.wss10.SecurityTokenReferenceType;
import org.apache.wss4j.common.bsp.BSPRule;
import org.apache.wss4j.common.ext.Attachment;
import org.apache.wss4j.common.ext.AttachmentRequestCallback;
import org.apache.wss4j.common.ext.AttachmentResultCallback;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.util.AttachmentUtils;
import org.apache.wss4j.stax.ext.WSInboundSecurityContext;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.ext.WSSSecurityProperties;
import org.apache.wss4j.stax.securityEvent.EncryptedPartSecurityEvent;
import org.apache.wss4j.stax.securityToken.WSSecurityTokenConstants;
import org.apache.wss4j.stax.utils.LimitingInputStream;
import org.apache.wss4j.stax.utils.WSSUtils;
import org.apache.xml.security.binding.xmldsig.KeyInfoType;
import org.apache.xml.security.binding.xmldsig.TransformType;
import org.apache.xml.security.binding.xmldsig.TransformsType;
import org.apache.xml.security.binding.xmlenc.CipherReferenceType;
import org.apache.xml.security.binding.xmlenc.EncryptedDataType;
import org.apache.xml.security.binding.xmlenc.ReferenceList;
import org.apache.xml.security.binding.xmlenc.ReferenceType;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.config.ConfigurationProperties;
import org.apache.xml.security.stax.config.TransformerAlgorithmMapper;
import org.apache.xml.security.stax.ext.DocumentContext;
import org.apache.xml.security.stax.ext.InboundSecurityContext;
import org.apache.xml.security.stax.ext.InputProcessorChain;
import org.apache.xml.security.stax.ext.SecurePart;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.ext.XMLSecurityProperties;
import org.apache.xml.security.stax.ext.XMLSecurityUtils;
import org.apache.xml.security.stax.ext.stax.XMLSecStartElement;
import org.apache.xml.security.stax.impl.processor.input.AbstractDecryptInputProcessor;
import org.apache.xml.security.stax.securityEvent.ContentEncryptedElementSecurityEvent;
import org.apache.xml.security.stax.securityEvent.EncryptedElementSecurityEvent;
import org.apache.xml.security.stax.securityEvent.TokenSecurityEvent;
import org.apache.xml.security.stax.securityToken.InboundSecurityToken;
import org.apache.xml.security.stax.securityToken.SecurityToken;

/**
 * Processor for decryption of EncryptedData XML structures
 */
public class DecryptInputProcessor extends AbstractDecryptInputProcessor {

    private static final transient org.slf4j.Logger LOG =
        org.slf4j.LoggerFactory.getLogger(DecryptInputProcessor.class);

    private static final Long MAX_ALLOWED_DECOMPRESSED_BYTES =
            Long.valueOf(ConfigurationProperties.getProperty("MaximumAllowedDecompressedBytes"));

    private List<DeferredAttachment> attachmentReferences = new ArrayList<>();

    public DecryptInputProcessor(KeyInfoType keyInfoType, ReferenceList referenceList,
                                 WSSSecurityProperties securityProperties, WSInboundSecurityContext securityContext)
            throws XMLSecurityException {

        super(keyInfoType, referenceList, securityProperties);
        checkBSPCompliance(keyInfoType, referenceList, securityContext, BSPRule.R3006);
    }

    private void checkBSPCompliance(KeyInfoType keyInfoType, ReferenceList referenceList, WSInboundSecurityContext securityContext,
                                    BSPRule bspRule) throws WSSecurityException {
        if (keyInfoType != null) {
            if (keyInfoType.getContent().size() != 1) {
                securityContext.handleBSPRule(BSPRule.R5424);
            }
            SecurityTokenReferenceType securityTokenReferenceType = XMLSecurityUtils.getQNameType(keyInfoType.getContent(),
                    WSSConstants.TAG_WSSE_SECURITY_TOKEN_REFERENCE);
            if (securityTokenReferenceType == null) {
                securityContext.handleBSPRule(BSPRule.R5426);
            }
        }

        if (referenceList != null) {
            List<JAXBElement<ReferenceType>> references = referenceList.getDataReferenceOrKeyReference();
            Iterator<JAXBElement<ReferenceType>> referenceTypeIterator = references.iterator();
            while (referenceTypeIterator.hasNext()) {
                ReferenceType referenceType = referenceTypeIterator.next().getValue();
                if (!referenceType.getURI().startsWith("#")) {
                    securityContext.handleBSPRule(bspRule);
                }
            }
        }
    }

    @Override
    protected InputStream applyTransforms(ReferenceType referenceType, InputStream inputStream) throws XMLSecurityException {
        if (referenceType != null) {
            TransformsType transformsType =
                    XMLSecurityUtils.getQNameType(referenceType.getAny(), XMLSecurityConstants.TAG_dsig_Transforms);
            if (transformsType != null) {
                List<TransformType> transformTypes = transformsType.getTransform();
                //to do don't forget to limit the count of transformations if more transformations will be supported!
                if (transformTypes.size() > 1) {
                    throw new XMLSecurityException("stax.encryption.Transforms.NotYetImplemented");
                }
                TransformType transformType = transformTypes.get(0);
                @SuppressWarnings("unchecked")
                Class<InputStream> transformerClass =
                        (Class<InputStream>) TransformerAlgorithmMapper.getTransformerClass(
                                transformType.getAlgorithm(), XMLSecurityConstants.DIRECTION.IN);
                try {
                    Constructor<InputStream> constructor = transformerClass.getConstructor(InputStream.class);
                    inputStream = new LimitingInputStream(
                            constructor.newInstance(inputStream), MAX_ALLOWED_DECOMPRESSED_BYTES);
                } catch (InvocationTargetException | NoSuchMethodException
                    | InstantiationException | IllegalAccessException e) {
                    throw new XMLSecurityException(e);
                }
            }
        }
        return inputStream;
    }

    @Override
    protected void handleEncryptedContent(
            InputProcessorChain inputProcessorChain, XMLSecStartElement parentStartXMLEvent,
            InboundSecurityToken inboundSecurityToken, EncryptedDataType encryptedDataType) throws XMLSecurityException {

        final DocumentContext documentContext = inputProcessorChain.getDocumentContext();
        List<QName> elementPath = parentStartXMLEvent.getElementPath();
        if (elementPath.size() == 2 && WSSUtils.isInSOAPBody(elementPath)) {
            //soap:body content encryption counts as EncryptedPart
            EncryptedPartSecurityEvent encryptedPartSecurityEvent =
                    new EncryptedPartSecurityEvent(inboundSecurityToken, true, documentContext.getProtectionOrder());
            encryptedPartSecurityEvent.setElementPath(elementPath);
            encryptedPartSecurityEvent.setXmlSecEvent(parentStartXMLEvent);
            encryptedPartSecurityEvent.setCorrelationID(encryptedDataType.getId());
            inputProcessorChain.getSecurityContext().registerSecurityEvent(encryptedPartSecurityEvent);
        } else {
            ContentEncryptedElementSecurityEvent contentEncryptedElementSecurityEvent =
                    new ContentEncryptedElementSecurityEvent(inboundSecurityToken, true, documentContext.getProtectionOrder());
            contentEncryptedElementSecurityEvent.setElementPath(elementPath);
            contentEncryptedElementSecurityEvent.setXmlSecEvent(parentStartXMLEvent);
            contentEncryptedElementSecurityEvent.setCorrelationID(encryptedDataType.getId());
            inputProcessorChain.getSecurityContext().registerSecurityEvent(contentEncryptedElementSecurityEvent);
        }
    }

    @Override
    protected void handleCipherReference(InputProcessorChain inputProcessorChain, EncryptedDataType encryptedDataType,
                                         Cipher cipher, InboundSecurityToken inboundSecurityToken) throws XMLSecurityException {

        String typeStr = encryptedDataType.getType();
        if (typeStr != null
            && (WSSConstants.SWA_ATTACHMENT_ENCRYPTED_DATA_TYPE_CONTENT_ONLY.equals(typeStr)
                || WSSConstants.SWA_ATTACHMENT_ENCRYPTED_DATA_TYPE_COMPLETE.equals(typeStr))) {

            CipherReferenceType cipherReferenceType = encryptedDataType.getCipherData().getCipherReference();
            if (cipherReferenceType == null) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_CHECK);
            }

            final String uri = cipherReferenceType.getURI();
            if (uri == null || uri.length() < 5) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_CHECK);
            }
            if (!uri.startsWith("cid:")) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_CHECK);
            }

            //we need to do a deferred processing of the attachments for two reasons:
            //1.) if an attachment is encrypted and signed the order is preserved
            //2.) the attachments are processed after the SOAP-Document which allows us to stream everything
            attachmentReferences.add(
                    new DeferredAttachment(encryptedDataType, cipher, inboundSecurityToken)
            );
        }
    }

    @Override
    protected InputStream handleXOPInclude(InputProcessorChain inputProcessorChain, EncryptedDataType encryptedDataType, String href,
                                           Cipher cipher, InboundSecurityToken inboundSecurityToken) throws XMLSecurityException {
        if (href == null || href.length() < 5) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_CHECK);
        }
        if (!href.startsWith("cid:")) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_CHECK);
        }

        final String attachmentId = AttachmentUtils.getAttachmentId(href);

        CallbackHandler attachmentCallbackHandler =
            ((WSSSecurityProperties) getSecurityProperties()).getAttachmentCallbackHandler();
        if (attachmentCallbackHandler == null) {
            throw new WSSecurityException(
                WSSecurityException.ErrorCode.INVALID_SECURITY,
                "empty", new Object[] {"no attachment callbackhandler supplied"}
            );
        }

        AttachmentRequestCallback attachmentRequestCallback = new AttachmentRequestCallback();
        attachmentRequestCallback.setAttachmentId(attachmentId);
        try {
            attachmentCallbackHandler.handle(new Callback[]{attachmentRequestCallback});
        } catch (Exception e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY, e);
        }
        List<Attachment> attachments = attachmentRequestCallback.getAttachments();
        if (attachments == null || attachments.isEmpty() || !attachmentId.equals(attachments.get(0).getId())) {
            throw new WSSecurityException(
                WSSecurityException.ErrorCode.INVALID_SECURITY,
                "empty", new Object[] {"Attachment not found"}
            );
        }

        final Attachment attachment = attachments.get(0);

        final String encAlgo = encryptedDataType.getEncryptionMethod().getAlgorithm();
        final Key symmetricKey =
            inboundSecurityToken.getSecretKey(encAlgo, XMLSecurityConstants.Enc, encryptedDataType.getId());

        return
            AttachmentUtils.setupAttachmentDecryptionStream(encAlgo, cipher, symmetricKey, attachment.getSourceStream());
    }

    @Override
    protected AbstractDecryptedEventReaderInputProcessor newDecryptedEventReaderInputProcessor(
            boolean encryptedHeader, XMLSecStartElement xmlSecStartElement, EncryptedDataType encryptedDataType,
            InboundSecurityToken inboundSecurityToken, InboundSecurityContext inboundSecurityContext) throws XMLSecurityException {

        // Check encryption algorithm against the required algorithm, if defined
        String encryptionAlgorithm = encryptedDataType.getEncryptionMethod().getAlgorithm();
        if (this.getSecurityProperties().getEncryptionSymAlgorithm() != null
            && !this.getSecurityProperties().getEncryptionSymAlgorithm().equals(encryptionAlgorithm)) {
            LOG.warn(
                "The Key encryption method does not match the requirement"
            );
            throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY);
        }

        if (!WSSConstants.NS_XENC_TRIPLE_DES.equals(encryptionAlgorithm)
                && !WSSConstants.NS_XENC_AES128.equals(encryptionAlgorithm)
                && !WSSConstants.NS_XENC11_AES128_GCM.equals(encryptionAlgorithm)
                && !WSSConstants.NS_XENC_AES256.equals(encryptionAlgorithm)
                && !WSSConstants.NS_XENC11_AES256_GCM.equals(encryptionAlgorithm)) {
            ((WSInboundSecurityContext) inboundSecurityContext).handleBSPRule(BSPRule.R5620);
        }

        return new DecryptedEventReaderInputProcessor(getSecurityProperties(),
                SecurePart.Modifier.getModifier(encryptedDataType.getType()),
                encryptedHeader, xmlSecStartElement, encryptedDataType, this, inboundSecurityToken);
    }

    @Override
    protected void handleSecurityToken(InboundSecurityToken inboundSecurityToken, InboundSecurityContext inboundSecurityContext,
                                       EncryptedDataType encryptedDataType) throws XMLSecurityException {
        inboundSecurityToken.addTokenUsage(WSSecurityTokenConstants.TokenUsage_Encryption);
        TokenSecurityEvent<? extends SecurityToken> tokenSecurityEvent =
            WSSUtils.createTokenSecurityEvent(inboundSecurityToken, encryptedDataType.getId());
        inboundSecurityContext.registerSecurityEvent(tokenSecurityEvent);
    }

    @Override
    public void doFinal(InputProcessorChain inputProcessorChain) throws XMLStreamException, XMLSecurityException {
        //find already processed references by the EncryptedDataHandler
        List<String> encryptedDataRefs = inputProcessorChain.getSecurityContext().getAsList(WSSConstants.PROP_ENCRYPTED_DATA_REFS);
        if (encryptedDataRefs != null && !encryptedDataRefs.isEmpty()) {
            Map<String, ReferenceType> references = getReferences();
            List<ReferenceType> processedReferences = getProcessedReferences();
            if (references != null) {
                Iterator<Map.Entry<String, ReferenceType>> iterator = references.entrySet().iterator();
                while (iterator.hasNext()) {
                    Map.Entry<String, ReferenceType> next = iterator.next();
                    final ReferenceType referenceType = next.getValue();
                    String uri = WSSUtils.dropReferenceMarker(referenceType.getURI());

                    Iterator<String> encryptedDataIterator = encryptedDataRefs.iterator();
                    while (encryptedDataIterator.hasNext()) {
                        String s = encryptedDataIterator.next();
                        if (s.equals(uri)) {
                            processedReferences.add(referenceType);
                        }
                    }
                }
            }
        }
        super.doFinal(inputProcessorChain);

        //now process the (deferred-) attachments:
        for (int i = 0; i < attachmentReferences.size(); i++) {
            DeferredAttachment deferredAttachment = attachmentReferences.get(i);

            final EncryptedDataType encryptedDataType = deferredAttachment.getEncryptedDataType();
            final InboundSecurityToken inboundSecurityToken = deferredAttachment.getInboundSecurityToken();
            final Cipher cipher = deferredAttachment.getCipher();
            final String uri = encryptedDataType.getCipherData().getCipherReference().getURI();
            final String attachmentId = AttachmentUtils.getAttachmentId(uri);

            CallbackHandler attachmentCallbackHandler =
                ((WSSSecurityProperties) getSecurityProperties()).getAttachmentCallbackHandler();
            if (attachmentCallbackHandler == null) {
                throw new WSSecurityException(
                    WSSecurityException.ErrorCode.INVALID_SECURITY,
                    "empty", new Object[] {"no attachment callbackhandler supplied"}
                );
            }

            AttachmentRequestCallback attachmentRequestCallback = new AttachmentRequestCallback();
            attachmentRequestCallback.setAttachmentId(attachmentId);
            try {
                attachmentCallbackHandler.handle(new Callback[]{attachmentRequestCallback});
            } catch (Exception e) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY, e);
            }
            List<Attachment> attachments = attachmentRequestCallback.getAttachments();
            if (attachments == null || attachments.isEmpty() || !attachmentId.equals(attachments.get(0).getId())) {
                throw new WSSecurityException(
                    WSSecurityException.ErrorCode.INVALID_SECURITY,
                    "empty", new Object[] {"Attachment not found"}
                );
            }

            final Attachment attachment = attachments.get(0);

            final String encAlgo = encryptedDataType.getEncryptionMethod().getAlgorithm();
            final Key symmetricKey =
                inboundSecurityToken.getSecretKey(encAlgo, XMLSecurityConstants.Enc, encryptedDataType.getId());

            InputStream attachmentInputStream =
                AttachmentUtils.setupAttachmentDecryptionStream(encAlgo, cipher, symmetricKey, attachment.getSourceStream());

            Attachment resultAttachment = new Attachment();
            resultAttachment.setId(attachment.getId());
            resultAttachment.setMimeType(encryptedDataType.getMimeType());
            resultAttachment.setSourceStream(attachmentInputStream);
            resultAttachment.addHeaders(attachment.getHeaders());

            if (WSSConstants.SWA_ATTACHMENT_ENCRYPTED_DATA_TYPE_COMPLETE.equals(encryptedDataType.getType())) {
                try {
                    AttachmentUtils.readAndReplaceEncryptedAttachmentHeaders(
                        resultAttachment.getHeaders(), attachmentInputStream);
                } catch (IOException e) {
                    throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY, e);
                }
            }

            AttachmentResultCallback attachmentResultCallback = new AttachmentResultCallback();
            attachmentResultCallback.setAttachment(resultAttachment);
            attachmentResultCallback.setAttachmentId(resultAttachment.getId());
            try {
                attachmentCallbackHandler.handle(new Callback[]{attachmentResultCallback});
            } catch (Exception e) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY, e);
            }

            // Create a security event for this encrypted Attachment
            final DocumentContext documentContext = inputProcessorChain.getDocumentContext();
            EncryptedPartSecurityEvent encryptedPartSecurityEvent =
                new EncryptedPartSecurityEvent(inboundSecurityToken, true, documentContext.getProtectionOrder());
            encryptedPartSecurityEvent.setAttachment(true);
            encryptedPartSecurityEvent.setCorrelationID(encryptedDataType.getId());
            inputProcessorChain.getSecurityContext().registerSecurityEvent(encryptedPartSecurityEvent);
        }
    }

    private static final class DeferredAttachment {

        private EncryptedDataType encryptedDataType;
        private Cipher cipher;
        private InboundSecurityToken inboundSecurityToken;

        private DeferredAttachment(
            EncryptedDataType encryptedDataType, Cipher cipher,
            InboundSecurityToken inboundSecurityToken) {

            this.encryptedDataType = encryptedDataType;
            this.cipher = cipher;
            this.inboundSecurityToken = inboundSecurityToken;
        }

        private EncryptedDataType getEncryptedDataType() {
            return encryptedDataType;
        }

        private Cipher getCipher() {
            return cipher;
        }

        private InboundSecurityToken getInboundSecurityToken() {
            return inboundSecurityToken;
        }
    }

    /**
     * The DecryptedEventReaderInputProcessor reads the decrypted stream with a StAX reader and
     * forwards the generated XMLEvents
     */
    class DecryptedEventReaderInputProcessor extends AbstractDecryptedEventReaderInputProcessor {

        DecryptedEventReaderInputProcessor(
                XMLSecurityProperties securityProperties, SecurePart.Modifier encryptionModifier,
                boolean encryptedHeader, XMLSecStartElement xmlSecStartElement,
                EncryptedDataType encryptedDataType,
                DecryptInputProcessor decryptInputProcessor,
                InboundSecurityToken inboundSecurityToken
        ) {
            super(securityProperties, encryptionModifier, encryptedHeader, xmlSecStartElement,
                    encryptedDataType, decryptInputProcessor, inboundSecurityToken);
        }

        @Override
        protected void handleEncryptedElement(
                InputProcessorChain inputProcessorChain, XMLSecStartElement xmlSecStartElement,
                InboundSecurityToken inboundSecurityToken, EncryptedDataType encryptedDataType) throws XMLSecurityException {

            //fire a SecurityEvent:
            final DocumentContext documentContext = inputProcessorChain.getDocumentContext();
            List<QName> elementPath = xmlSecStartElement.getElementPath();
            if (elementPath.size() == 3 && WSSUtils.isInSOAPHeader(elementPath)) {
                EncryptedPartSecurityEvent encryptedPartSecurityEvent =
                        new EncryptedPartSecurityEvent(inboundSecurityToken, true, documentContext.getProtectionOrder());
                encryptedPartSecurityEvent.setElementPath(elementPath);
                encryptedPartSecurityEvent.setXmlSecEvent(xmlSecStartElement);
                encryptedPartSecurityEvent.setCorrelationID(encryptedDataType.getId());
                inputProcessorChain.getSecurityContext().registerSecurityEvent(encryptedPartSecurityEvent);
            } else {
                EncryptedElementSecurityEvent encryptedElementSecurityEvent =
                        new EncryptedElementSecurityEvent(inboundSecurityToken, true, documentContext.getProtectionOrder());
                encryptedElementSecurityEvent.setElementPath(elementPath);
                encryptedElementSecurityEvent.setXmlSecEvent(xmlSecStartElement);
                encryptedElementSecurityEvent.setCorrelationID(encryptedDataType.getId());
                inputProcessorChain.getSecurityContext().registerSecurityEvent(encryptedElementSecurityEvent);
            }
        }
    }
}
