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
package org.swssf.xmlsec.impl.processor.output;

import org.apache.commons.codec.binary.Base64;
import org.swssf.xmlsec.ext.*;
import org.swssf.xmlsec.impl.SignaturePartDef;
import org.swssf.xmlsec.impl.algorithms.SignatureAlgorithm;
import org.swssf.xmlsec.impl.algorithms.SignatureAlgorithmFactory;
import org.swssf.xmlsec.impl.util.SignerOutputStream;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.XMLEvent;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.InvocationTargetException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.*;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public abstract class AbstractSignatureEndingOutputProcessor extends AbstractBufferingOutputProcessor {

    private List<SignaturePartDef> signaturePartDefList;

    public AbstractSignatureEndingOutputProcessor(XMLSecurityProperties securityProperties, XMLSecurityConstants.Action action, AbstractSignatureOutputProcessor signatureOutputProcessor) throws XMLSecurityException {
        super(securityProperties, action);
        signaturePartDefList = signatureOutputProcessor.getSignaturePartDefList();
    }

    /*
        <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="Signature-1022834285">
            <ds:SignedInfo>
                <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />
                <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1" />
                <ds:Reference URI="#id-1612925417">
                    <ds:Transforms>
                        <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />
                    </ds:Transforms>
                    <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1" />
                    <ds:DigestValue>cy/khx5N6UobCJ1EbX+qnrGID2U=</ds:DigestValue>
                </ds:Reference>
                <ds:Reference URI="#Timestamp-1106985890">
                    <ds:Transforms>
                        <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />
                    </ds:Transforms>
                    <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1" />
                    <ds:DigestValue>+p5YRII6uvUdsJ7XLKkWx1CBewE=</ds:DigestValue>
                </ds:Reference>
            </ds:SignedInfo>
            <ds:SignatureValue>
                Izg1FlI9oa4gOon2vTXi7V0EpiyCUazECVGYflbXq7/3GF8ThKGDMpush/fo1I2NVjEFTfmT2WP/
                +ZG5N2jASFptrcGbsqmuLE5JbxUP1TVKb9SigKYcOQJJ8klzmVfPXnSiRZmIU+DUT2UXopWnGNFL
                TwY0Uxja4ZuI6U8m8Tg=
            </ds:SignatureValue>
            <ds:KeyInfo Id="KeyId-1043455692">
                <wsse:SecurityTokenReference xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" wsu:Id="STRId-1008354042">
                    <wsse:Reference xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" URI="#CertId-3458500" ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3" />
                </wsse:SecurityTokenReference>
            </ds:KeyInfo>
        </ds:Signature>
    */

    @Override
    public abstract void doFinal(OutputProcessorChain outputProcessorChain) throws XMLStreamException, XMLSecurityException;

    public void processHeaderEvent(OutputProcessorChain outputProcessorChain) throws XMLStreamException, XMLSecurityException {

        OutputProcessorChain subOutputProcessorChain = outputProcessorChain.createSubChain(this);

        Map<QName, String> attributes = new HashMap<QName, String>();
        attributes.put(XMLSecurityConstants.ATT_NULL_Id, "Signature-" + UUID.randomUUID().toString());
        createStartElementAndOutputAsEvent(subOutputProcessorChain, XMLSecurityConstants.TAG_dsig_Signature, attributes);

        SignatureAlgorithm signatureAlgorithm;

        try {
            signatureAlgorithm = SignatureAlgorithmFactory.getInstance().getSignatureAlgorithm(getSecurityProperties().getSignatureAlgorithm());
        } catch (NoSuchAlgorithmException e) {
            throw new XMLSecurityException(XMLSecurityException.ErrorCode.FAILED_SIGNATURE, e);
        } catch (NoSuchProviderException e) {
            throw new XMLSecurityException(XMLSecurityException.ErrorCode.FAILURE, "noSecProvider", e);
        }

        String tokenId = outputProcessorChain.getSecurityContext().get(XMLSecurityConstants.PROP_USE_THIS_TOKEN_ID_FOR_SIGNATURE);
        if (tokenId == null) {
            throw new XMLSecurityException(XMLSecurityException.ErrorCode.FAILED_SIGNATURE);
        }
        SecurityTokenProvider wrappingSecurityTokenProvider = outputProcessorChain.getSecurityContext().getSecurityTokenProvider(tokenId);
        if (wrappingSecurityTokenProvider == null) {
            throw new XMLSecurityException(XMLSecurityException.ErrorCode.FAILED_SIGNATURE);
        }
        final SecurityToken wrappingSecurityToken = wrappingSecurityTokenProvider.getSecurityToken(null);
        if (wrappingSecurityToken == null) {
            throw new XMLSecurityException(XMLSecurityException.ErrorCode.FAILED_SIGNATURE);
        }

        signatureAlgorithm.engineInitSign(wrappingSecurityToken.getSecretKey(getSecurityProperties().getSignatureAlgorithm(), null));

        SignedInfoProcessor signedInfoProcessor = newSignedInfoProcessor(signatureAlgorithm);
        subOutputProcessorChain.addProcessor(signedInfoProcessor);

        createStartElementAndOutputAsEvent(subOutputProcessorChain, XMLSecurityConstants.TAG_dsig_SignedInfo, null);

        attributes = new HashMap<QName, String>();
        attributes.put(XMLSecurityConstants.ATT_NULL_Algorithm, getSecurityProperties().getSignatureCanonicalizationAlgorithm());
        createStartElementAndOutputAsEvent(subOutputProcessorChain, XMLSecurityConstants.TAG_dsig_CanonicalizationMethod, attributes);
        createEndElementAndOutputAsEvent(subOutputProcessorChain, XMLSecurityConstants.TAG_dsig_CanonicalizationMethod);

        attributes = new HashMap<QName, String>();
        attributes.put(XMLSecurityConstants.ATT_NULL_Algorithm, getSecurityProperties().getSignatureAlgorithm());
        createStartElementAndOutputAsEvent(subOutputProcessorChain, XMLSecurityConstants.TAG_dsig_SignatureMethod, attributes);
        createEndElementAndOutputAsEvent(subOutputProcessorChain, XMLSecurityConstants.TAG_dsig_SignatureMethod);

        Iterator<SignaturePartDef> signaturePartDefIterator = signaturePartDefList.iterator();
        while (signaturePartDefIterator.hasNext()) {
            SignaturePartDef signaturePartDef = signaturePartDefIterator.next();
            attributes = new HashMap<QName, String>();
            attributes.put(XMLSecurityConstants.ATT_NULL_URI, "#" + signaturePartDef.getSigRefId());
            createStartElementAndOutputAsEvent(subOutputProcessorChain, XMLSecurityConstants.TAG_dsig_Reference, attributes);
            createStartElementAndOutputAsEvent(subOutputProcessorChain, XMLSecurityConstants.TAG_dsig_Transforms, null);
            createTransformsStructureForSignature(subOutputProcessorChain, signaturePartDef);
            createEndElementAndOutputAsEvent(subOutputProcessorChain, XMLSecurityConstants.TAG_dsig_Transforms);

            attributes = new HashMap<QName, String>();
            attributes.put(XMLSecurityConstants.ATT_NULL_Algorithm, getSecurityProperties().getSignatureDigestAlgorithm());
            createStartElementAndOutputAsEvent(subOutputProcessorChain, XMLSecurityConstants.TAG_dsig_DigestMethod, attributes);
            createEndElementAndOutputAsEvent(subOutputProcessorChain, XMLSecurityConstants.TAG_dsig_DigestMethod);
            createStartElementAndOutputAsEvent(subOutputProcessorChain, XMLSecurityConstants.TAG_dsig_DigestValue, null);
            createCharactersAndOutputAsEvent(subOutputProcessorChain, signaturePartDef.getDigestValue());
            createEndElementAndOutputAsEvent(subOutputProcessorChain, XMLSecurityConstants.TAG_dsig_DigestValue);
            createEndElementAndOutputAsEvent(subOutputProcessorChain, XMLSecurityConstants.TAG_dsig_Reference);
        }

        createEndElementAndOutputAsEvent(subOutputProcessorChain, XMLSecurityConstants.TAG_dsig_SignedInfo);
        subOutputProcessorChain.removeProcessor(signedInfoProcessor);

        createStartElementAndOutputAsEvent(subOutputProcessorChain, XMLSecurityConstants.TAG_dsig_SignatureValue, null);
        final byte[] signatureValue = signedInfoProcessor.getSignatureValue();
        createCharactersAndOutputAsEvent(subOutputProcessorChain, new Base64(76, new byte[]{'\n'}).encodeToString(signatureValue));
        createEndElementAndOutputAsEvent(subOutputProcessorChain, XMLSecurityConstants.TAG_dsig_SignatureValue);

        attributes = new HashMap<QName, String>();
        attributes.put(XMLSecurityConstants.ATT_NULL_Id, "KeyId-" + UUID.randomUUID().toString());
        createStartElementAndOutputAsEvent(subOutputProcessorChain, XMLSecurityConstants.TAG_dsig_KeyInfo, attributes);
        createKeyInfoStructureForSignature(subOutputProcessorChain, wrappingSecurityToken, getSecurityProperties().isUseSingleCert());
        createEndElementAndOutputAsEvent(subOutputProcessorChain, XMLSecurityConstants.TAG_dsig_KeyInfo);
        createEndElementAndOutputAsEvent(subOutputProcessorChain, XMLSecurityConstants.TAG_dsig_Signature);
    }

    protected SignedInfoProcessor newSignedInfoProcessor(SignatureAlgorithm signatureAlgorithm) throws XMLSecurityException {
        SignedInfoProcessor signedInfoProcessor = new SignedInfoProcessor(getSecurityProperties(), getAction(), signatureAlgorithm);
        signedInfoProcessor.getAfterProcessors().add(AbstractSignatureEndingOutputProcessor.class.getName());
        return signedInfoProcessor;
    }

    protected abstract void createTransformsStructureForSignature(
            OutputProcessorChain subOutputProcessorChain,
            SignaturePartDef signaturePartDef) throws XMLStreamException, XMLSecurityException;

    protected abstract void createKeyInfoStructureForSignature(
            OutputProcessorChain outputProcessorChain,
            SecurityToken securityToken,
            boolean useSingleCertificate) throws XMLStreamException, XMLSecurityException;


    public class SignedInfoProcessor extends AbstractOutputProcessor {

        private SignerOutputStream signerOutputStream;
        private OutputStream bufferedSignerOutputStream;
        private Transformer transformer;
        private byte[] signatureValue = null;

        public SignedInfoProcessor(XMLSecurityProperties securityProperties, XMLSecurityConstants.Action action, SignatureAlgorithm signatureAlgorithm) throws XMLSecurityException {
            super(securityProperties, action);

            signerOutputStream = new SignerOutputStream(signatureAlgorithm);
            bufferedSignerOutputStream = new BufferedOutputStream(signerOutputStream);

            try {
                transformer = XMLSecurityUtils.getTransformer(null, this.bufferedSignerOutputStream, getSecurityProperties().getSignatureCanonicalizationAlgorithm());
            } catch (NoSuchMethodException e) {
                throw new XMLSecurityException(XMLSecurityException.ErrorCode.FAILED_SIGNATURE, e);
            } catch (InstantiationException e) {
                throw new XMLSecurityException(XMLSecurityException.ErrorCode.FAILED_SIGNATURE, e);
            } catch (IllegalAccessException e) {
                throw new XMLSecurityException(XMLSecurityException.ErrorCode.FAILED_SIGNATURE, e);
            } catch (InvocationTargetException e) {
                throw new XMLSecurityException(XMLSecurityException.ErrorCode.FAILED_SIGNATURE, e);
            }
        }

        public byte[] getSignatureValue() throws XMLSecurityException {
            if (signatureValue != null) {
                return signatureValue;
            }
            try {
                bufferedSignerOutputStream.close();
                signatureValue = signerOutputStream.sign();
                return signatureValue;
            } catch (IOException e) {
                throw new XMLSecurityException(XMLSecurityException.ErrorCode.FAILED_SIGNATURE, e);
            }
        }

        @Override
        public void processEvent(XMLEvent xmlEvent, OutputProcessorChain outputProcessorChain) throws XMLStreamException, XMLSecurityException {
            transformer.transform(xmlEvent);
            outputProcessorChain.processEvent(xmlEvent);
        }
    }
}
