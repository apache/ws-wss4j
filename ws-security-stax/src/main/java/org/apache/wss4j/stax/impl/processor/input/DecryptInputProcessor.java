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

import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.Iterator;
import java.util.List;

import javax.xml.bind.JAXBElement;
import javax.xml.namespace.QName;

import org.apache.wss4j.binding.wss10.SecurityTokenReferenceType;
import org.apache.wss4j.common.bsp.BSPRule;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.xml.security.binding.xmldsig.KeyInfoType;
import org.apache.xml.security.binding.xmldsig.TransformType;
import org.apache.xml.security.binding.xmldsig.TransformsType;
import org.apache.xml.security.binding.xmlenc.EncryptedDataType;
import org.apache.xml.security.binding.xmlenc.ReferenceList;
import org.apache.xml.security.binding.xmlenc.ReferenceType;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.config.ConfigurationProperties;
import org.apache.xml.security.stax.config.TransformerAlgorithmMapper;
import org.apache.xml.security.stax.ext.*;
import org.apache.xml.security.stax.ext.stax.XMLSecStartElement;
import org.apache.xml.security.stax.impl.processor.input.AbstractDecryptInputProcessor;
import org.apache.xml.security.stax.impl.util.LimitingInputStream;
import org.apache.xml.security.stax.securityEvent.ContentEncryptedElementSecurityEvent;
import org.apache.xml.security.stax.securityEvent.EncryptedElementSecurityEvent;
import org.apache.xml.security.stax.securityEvent.TokenSecurityEvent;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.ext.WSSSecurityProperties;
import org.apache.wss4j.stax.ext.WSSUtils;
import org.apache.wss4j.stax.ext.WSSecurityContext;
import org.apache.wss4j.stax.securityEvent.EncryptedPartSecurityEvent;

/**
 * Processor for decryption of EncryptedData XML structures
 */
public class DecryptInputProcessor extends AbstractDecryptInputProcessor {

    private static final Long maximumAllowedDecompressedBytes =
            Long.valueOf(ConfigurationProperties.getProperty("MaximumAllowedDecompressedBytes"));

    public DecryptInputProcessor(KeyInfoType keyInfoType, ReferenceList referenceList,
                                 WSSSecurityProperties securityProperties, WSSecurityContext securityContext)
            throws XMLSecurityException {

        super(keyInfoType, referenceList, securityProperties);
        checkBSPCompliance(keyInfoType, referenceList, securityContext, BSPRule.R3006);
    }

    private void checkBSPCompliance(KeyInfoType keyInfoType, ReferenceList referenceList, WSSecurityContext securityContext,
                                    BSPRule bspRule) throws WSSecurityException {
        if (keyInfoType != null) {
            if (keyInfoType.getContent().size() != 1) {
                securityContext.handleBSPRule(BSPRule.R5424);
            }
            SecurityTokenReferenceType securityTokenReferenceType = XMLSecurityUtils.getQNameType(keyInfoType.getContent(),
                    WSSConstants.TAG_wsse_SecurityTokenReference);
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
                            constructor.newInstance(inputStream),
                            maximumAllowedDecompressedBytes);
                } catch (InvocationTargetException e) {
                    throw new XMLSecurityException(e);
                } catch (NoSuchMethodException e) {
                    throw new XMLSecurityException(e);
                } catch (InstantiationException e) {
                    throw new XMLSecurityException(e);
                } catch (IllegalAccessException e) {
                    throw new XMLSecurityException(e);
                }
            }
        }
        return inputStream;
    }

    @Override
    protected void handleEncryptedContent(
            InputProcessorChain inputProcessorChain, XMLSecStartElement parentStartXMLEvent,
            SecurityToken securityToken, EncryptedDataType encryptedDataType) throws XMLSecurityException {

        final DocumentContext documentContext = inputProcessorChain.getDocumentContext();
        List<QName> elementPath = parentStartXMLEvent.getElementPath();
        if (elementPath.size() == 2 && WSSUtils.isInSOAPBody(elementPath)) {
            //soap:body content encryption counts as EncryptedPart
            EncryptedPartSecurityEvent encryptedPartSecurityEvent =
                    new EncryptedPartSecurityEvent(securityToken, true, documentContext.getProtectionOrder());
            encryptedPartSecurityEvent.setElementPath(elementPath);
            encryptedPartSecurityEvent.setXmlSecEvent(parentStartXMLEvent);
            encryptedPartSecurityEvent.setCorrelationID(encryptedDataType.getId());
            inputProcessorChain.getSecurityContext().registerSecurityEvent(encryptedPartSecurityEvent);
        } else {
            ContentEncryptedElementSecurityEvent contentEncryptedElementSecurityEvent =
                    new ContentEncryptedElementSecurityEvent(securityToken, true, documentContext.getProtectionOrder());
            contentEncryptedElementSecurityEvent.setElementPath(elementPath);
            contentEncryptedElementSecurityEvent.setXmlSecEvent(parentStartXMLEvent);
            contentEncryptedElementSecurityEvent.setCorrelationID(encryptedDataType.getId());
            inputProcessorChain.getSecurityContext().registerSecurityEvent(contentEncryptedElementSecurityEvent);
        }
    }

    @Override
    protected AbstractDecryptedEventReaderInputProcessor newDecryptedEventReaderInputProcessor(
            boolean encryptedHeader, XMLSecStartElement xmlSecStartElement, EncryptedDataType encryptedDataType,
            SecurityToken securityToken, SecurityContext securityContext) throws XMLSecurityException {

        String encryptionAlgorithm = encryptedDataType.getEncryptionMethod().getAlgorithm();
        if (!WSSConstants.NS_XENC_TRIPLE_DES.equals(encryptionAlgorithm)
                && !WSSConstants.NS_XENC_AES128.equals(encryptionAlgorithm)
                && !WSSConstants.NS_XENC11_AES128_GCM.equals(encryptionAlgorithm)
                && !WSSConstants.NS_XENC_AES256.equals(encryptionAlgorithm)
                && !WSSConstants.NS_XENC11_AES256_GCM.equals(encryptionAlgorithm)) {
            ((WSSecurityContext) securityContext).handleBSPRule(BSPRule.R5620);
        }

        return new DecryptedEventReaderInputProcessor(getSecurityProperties(),
                SecurePart.Modifier.getModifier(encryptedDataType.getType()),
                encryptedHeader, xmlSecStartElement, encryptedDataType, this, securityToken);
    }

    @Override
    protected void handleSecurityToken(SecurityToken securityToken, SecurityContext securityContext,
                                       EncryptedDataType encryptedDataType) throws XMLSecurityException {
        securityToken.addTokenUsage(SecurityToken.TokenUsage.Encryption);
        TokenSecurityEvent tokenSecurityEvent = WSSUtils.createTokenSecurityEvent(securityToken, encryptedDataType.getId());
        securityContext.registerSecurityEvent(tokenSecurityEvent);
    }
    
    /*
   <xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" Id="EncDataId-1612925417" Type="http://www.w3.org/2001/04/xmlenc#Content">
       <xenc:EncryptionMethod xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" Algorithm="http://www.w3.org/2001/04/xmlenc#aes256-cbc" />
       <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
           <wsse:SecurityTokenReference xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
               <wsse:Reference xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" URI="#EncKeyId-1483925398" />
           </wsse:SecurityTokenReference>
       </ds:KeyInfo>
       <xenc:CipherData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">
           <xenc:CipherValue xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">
           ...
           </xenc:CipherValue>
       </xenc:CipherData>
   </xenc:EncryptedData>
    */

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
                SecurityToken securityToken
        ) {
            super(securityProperties, encryptionModifier, encryptedHeader, xmlSecStartElement,
                    encryptedDataType, decryptInputProcessor, securityToken);
        }

        @Override
        protected void handleEncryptedElement(
                InputProcessorChain inputProcessorChain, XMLSecStartElement xmlSecStartElement,
                SecurityToken securityToken, EncryptedDataType encryptedDataType) throws XMLSecurityException {

            //fire a SecurityEvent:
            final DocumentContext documentContext = inputProcessorChain.getDocumentContext();
            List<QName> elementPath = xmlSecStartElement.getElementPath();
            if (elementPath.size() == 3 && WSSUtils.isInSOAPHeader(elementPath)) {
                EncryptedPartSecurityEvent encryptedPartSecurityEvent =
                        new EncryptedPartSecurityEvent(securityToken, true, documentContext.getProtectionOrder());
                encryptedPartSecurityEvent.setElementPath(elementPath);
                encryptedPartSecurityEvent.setXmlSecEvent(xmlSecStartElement);
                encryptedPartSecurityEvent.setCorrelationID(encryptedDataType.getId());
                inputProcessorChain.getSecurityContext().registerSecurityEvent(encryptedPartSecurityEvent);
            } else {
                EncryptedElementSecurityEvent encryptedElementSecurityEvent =
                        new EncryptedElementSecurityEvent(securityToken, true, documentContext.getProtectionOrder());
                encryptedElementSecurityEvent.setElementPath(elementPath);
                encryptedElementSecurityEvent.setXmlSecEvent(xmlSecStartElement);
                encryptedElementSecurityEvent.setCorrelationID(encryptedDataType.getId());
                inputProcessorChain.getSecurityContext().registerSecurityEvent(encryptedElementSecurityEvent);
            }
        }
    }
}
