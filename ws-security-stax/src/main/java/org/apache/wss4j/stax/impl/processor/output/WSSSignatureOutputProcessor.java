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
package org.apache.wss4j.stax.impl.processor.output;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.Attribute;

import org.apache.wss4j.common.ext.Attachment;
import org.apache.wss4j.common.ext.AttachmentRequestCallback;
import org.apache.wss4j.common.ext.AttachmentResultCallback;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.ext.WSSSecurityProperties;
import org.apache.wss4j.stax.impl.transformer.AttachmentContentSignatureTransform;
import org.apache.wss4j.stax.utils.WSSUtils;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.ext.OutputProcessorChain;
import org.apache.xml.security.stax.ext.SecurePart;
import org.apache.xml.security.stax.ext.Transformer;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.ext.stax.XMLSecAttribute;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;
import org.apache.xml.security.stax.ext.stax.XMLSecStartElement;
import org.apache.xml.security.stax.impl.SignaturePartDef;
import org.apache.xml.security.stax.impl.processor.output.AbstractSignatureOutputProcessor;
import org.apache.xml.security.stax.impl.util.DigestOutputStream;
import org.apache.xml.security.stax.impl.util.IDGenerator;
import org.apache.xml.security.utils.Base64;

public class WSSSignatureOutputProcessor extends AbstractSignatureOutputProcessor {

    private static final org.slf4j.Logger LOG =
        org.slf4j.LoggerFactory.getLogger(WSSSignatureOutputProcessor.class);

    public WSSSignatureOutputProcessor() throws XMLSecurityException {
        super();
    }

    @Override
    public void init(OutputProcessorChain outputProcessorChain) throws XMLSecurityException {
        super.init(outputProcessorChain);
        WSSSignatureEndingOutputProcessor signatureEndingOutputProcessor = new WSSSignatureEndingOutputProcessor(this);
        signatureEndingOutputProcessor.setXMLSecurityProperties(getSecurityProperties());
        signatureEndingOutputProcessor.setAction(getAction());
        signatureEndingOutputProcessor.init(outputProcessorChain);
    }

    @Override
    public void processEvent(XMLSecEvent xmlSecEvent, OutputProcessorChain outputProcessorChain) 
        throws XMLStreamException, XMLSecurityException {
        if (xmlSecEvent.getEventType() == XMLStreamConstants.START_ELEMENT) {
            XMLSecStartElement xmlSecStartElement = xmlSecEvent.asStartElement();

            //avoid double signature when child elements matches too
            if (getActiveInternalSignatureOutputProcessor() == null) {
                SecurePart securePart = securePartMatches(xmlSecStartElement, outputProcessorChain, WSSConstants.SIGNATURE_PARTS);
                if (securePart != null) {
                    LOG.debug("Matched securePart for signature");

                    SignaturePartDef signaturePartDef = new SignaturePartDef();
                    signaturePartDef.setSecurePart(securePart);
                    signaturePartDef.setTransforms(securePart.getTransforms());
                    if (signaturePartDef.getTransforms() == null) {
                        signaturePartDef.setTransforms(new String[]{XMLSecurityConstants.NS_C14N_EXCL_OMIT_COMMENTS});
                    }
                    signaturePartDef.setExcludeVisibleC14Nprefixes(true);
                    signaturePartDef.setDigestAlgo(securePart.getDigestMethod());
                    if (signaturePartDef.getDigestAlgo() == null) {
                        signaturePartDef.setDigestAlgo(getSecurityProperties().getSignatureDigestAlgorithm());
                    }

                    if (securePart.getIdToSign() == null) {
                        signaturePartDef.setGenerateXPointer(securePart.isGenerateXPointer());
                        signaturePartDef.setSigRefId(IDGenerator.generateID(null));

                        Attribute attribute = xmlSecStartElement.getAttributeByName(WSSConstants.ATT_WSU_ID);
                        if (attribute != null) {
                            signaturePartDef.setSigRefId(attribute.getValue());
                        } else {
                            List<XMLSecAttribute> attributeList = new ArrayList<>(1);
                            attributeList.add(createAttribute(WSSConstants.ATT_WSU_ID, signaturePartDef.getSigRefId()));
                            xmlSecEvent = addAttributes(xmlSecStartElement, attributeList);
                        }
                    } else {
                        if (WSSConstants.SOAPMESSAGE_NS10_STR_TRANSFORM.equals(securePart.getName().getLocalPart())) {
                            signaturePartDef.setSigRefId(securePart.getIdToReference());
                            String[] transforms = new String[]{
                                    WSSConstants.SOAPMESSAGE_NS10_STR_TRANSFORM,
                                    WSSConstants.NS_C14N_EXCL
                            };
                            signaturePartDef.setTransforms(transforms);
                        } else {
                            signaturePartDef.setSigRefId(securePart.getIdToSign());
                        }
                    }

                    getSignaturePartDefList().add(signaturePartDef);
                    InternalSignatureOutputProcessor internalSignatureOutputProcessor =
                            new InternalWSSSignatureOutputProcessor(signaturePartDef, xmlSecStartElement);
                    internalSignatureOutputProcessor.setXMLSecurityProperties(getSecurityProperties());
                    internalSignatureOutputProcessor.setAction(getAction());
                    internalSignatureOutputProcessor.addAfterProcessor(WSSSignatureOutputProcessor.class.getName());
                    internalSignatureOutputProcessor.addBeforeProcessor(WSSSignatureEndingOutputProcessor.class.getName());
                    internalSignatureOutputProcessor.init(outputProcessorChain);

                    setActiveInternalSignatureOutputProcessor(internalSignatureOutputProcessor);
                    //we can remove this processor when the whole body will be signed since there is
                    //nothing more which can be signed.
                    if (WSSConstants.TAG_SOAP_BODY_LN.equals(xmlSecStartElement.getName().getLocalPart())
                            && WSSUtils.isInSOAPBody(xmlSecStartElement)) {
                        doFinalInternal(outputProcessorChain);
                        outputProcessorChain.removeProcessor(this);
                    }
                }
            }
        }
        outputProcessorChain.processEvent(xmlSecEvent);
    }

    @Override
    protected void digestExternalReference(
            OutputProcessorChain outputProcessorChain, SecurePart securePart)
            throws XMLSecurityException, XMLStreamException {

        if (securePart.getExternalReference() != null && securePart.getExternalReference().startsWith("cid:")) {

            CallbackHandler attachmentCallbackHandler =
                    ((WSSSecurityProperties) getSecurityProperties()).getAttachmentCallbackHandler();
            if (attachmentCallbackHandler == null) {
                throw new WSSecurityException(
                        WSSecurityException.ErrorCode.FAILED_SIGNATURE,
                        "empty",
                        new Object[] {"no attachment callbackhandler supplied"}
                );
            }

            AttachmentRequestCallback attachmentRequestCallback = new AttachmentRequestCallback();
            String id = securePart.getExternalReference().substring("cid:".length());
            attachmentRequestCallback.setAttachmentId(id);
            try {
                attachmentCallbackHandler.handle(new Callback[]{attachmentRequestCallback});
            } catch (Exception e) {
                throw new WSSecurityException(
                        WSSecurityException.ErrorCode.FAILED_SIGNATURE, e
                );
            }
            List<Attachment> attachments = attachmentRequestCallback.getAttachments();
            if (attachments != null) {
                for (int i = 0; i < attachments.size(); i++) {
                    final Attachment attachment = attachments.get(i);

                    SignaturePartDef signaturePartDef = new SignaturePartDef();
                    signaturePartDef.setSecurePart(securePart);
                    signaturePartDef.setSigRefId("cid:" + attachment.getId());
                    signaturePartDef.setExternalResource(true);
                    signaturePartDef.setTransforms(securePart.getTransforms());
                    if (signaturePartDef.getTransforms() == null) {
                        if (securePart.getModifier() == SecurePart.Modifier.Element) {
                            signaturePartDef.setTransforms(new String[]{WSSConstants.SWA_ATTACHMENT_COMPLETE_SIG_TRANS});
                        } else {
                            signaturePartDef.setTransforms(new String[]{WSSConstants.SWA_ATTACHMENT_CONTENT_SIG_TRANS});
                        }
                    }
                    signaturePartDef.setExcludeVisibleC14Nprefixes(true);
                    signaturePartDef.setDigestAlgo(securePart.getDigestMethod());
                    if (signaturePartDef.getDigestAlgo() == null) {
                        signaturePartDef.setDigestAlgo(getSecurityProperties().getSignatureDigestAlgorithm());
                    }

                    DigestOutputStream digestOutputStream = createMessageDigestOutputStream(signaturePartDef.getDigestAlgo());
                    InputStream inputStream = attachment.getSourceStream();
                    if (!inputStream.markSupported()) {
                        inputStream = new BufferedInputStream(inputStream);
                    }
                    inputStream.mark(Integer.MAX_VALUE); //we can process at maximum 2G with the standard jdk streams

                    try {
                        Transformer transformer = buildTransformerChain(digestOutputStream, signaturePartDef, null);

                        Map<String, Object> transformerProperties = new HashMap<>(2);
                        transformerProperties.put(
                                AttachmentContentSignatureTransform.ATTACHMENT, attachment);
                        transformer.setProperties(transformerProperties);
                        transformer.transform(inputStream);
                        transformer.doFinal();

                        digestOutputStream.close();

                        //reset the inputStream to be able to reuse it
                        inputStream.reset();
                    } catch (IOException | XMLStreamException e) {
                        throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_SIGNATURE, e);
                    }

                    String calculatedDigest = Base64.encode(digestOutputStream.getDigestValue());
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Calculated Digest: " + calculatedDigest);
                    }

                    signaturePartDef.setDigestValue(calculatedDigest);

                    //create a new attachment and do the result callback
                    Attachment resultAttachment = new Attachment();
                    resultAttachment.setId(attachment.getId());
                    resultAttachment.setMimeType(attachment.getMimeType());
                    resultAttachment.addHeaders(attachment.getHeaders());
                    resultAttachment.setSourceStream(inputStream);

                    AttachmentResultCallback attachmentResultCallback = new AttachmentResultCallback();
                    attachmentResultCallback.setAttachmentId(resultAttachment.getId());
                    attachmentResultCallback.setAttachment(resultAttachment);
                    try {
                        attachmentCallbackHandler.handle(new Callback[]{attachmentResultCallback});
                    } catch (Exception e) {
                        throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_SIGNATURE, e);
                    }

                    getSignaturePartDefList().add(signaturePartDef);
                }
            }
        } else {
            super.digestExternalReference(outputProcessorChain, securePart);
        }
    }

    @Override
    protected SecurePart securePartMatches(XMLSecStartElement xmlSecStartElement, Map<Object, SecurePart> secureParts) {

        if (!xmlSecStartElement.getOnElementDeclaredAttributes().isEmpty()) {
            Attribute attribute = xmlSecStartElement.getAttributeByName(WSSConstants.ATT_WSU_ID);
            if (attribute != null) {
                SecurePart securePart = secureParts.get(attribute.getValue());
                if (securePart != null) {
                    return securePart;
                }
            }
            attribute = xmlSecStartElement.getAttributeByName(WSSConstants.ATT_NULL_Id);
            if (attribute != null) {
                SecurePart securePart = secureParts.get(attribute.getValue());
                if (securePart != null) {
                    return securePart;
                }
            }
            attribute = xmlSecStartElement.getAttributeByName(WSSConstants.ATT_NULL_ID);
            if (attribute != null) {
                SecurePart securePart = secureParts.get(attribute.getValue());
                if (securePart != null) {
                    return securePart;
                }
            }
            attribute = xmlSecStartElement.getAttributeByName(WSSConstants.ATT_NULL_ASSERTION_ID);
            if (attribute != null) {
                SecurePart securePart = secureParts.get(attribute.getValue());
                if (securePart != null) {
                    return securePart;
                }
            }
        }

        return secureParts.get(xmlSecStartElement.getName());
    }

    class InternalWSSSignatureOutputProcessor extends InternalSignatureOutputProcessor {

        public InternalWSSSignatureOutputProcessor(SignaturePartDef signaturePartDef, XMLSecStartElement xmlSecStartElement) 
            throws XMLSecurityException {
            super(signaturePartDef, xmlSecStartElement);
            this.addBeforeProcessor(InternalWSSSignatureOutputProcessor.class.getName());
        }
    }
}
