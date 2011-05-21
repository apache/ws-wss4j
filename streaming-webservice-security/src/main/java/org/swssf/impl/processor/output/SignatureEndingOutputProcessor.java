/**
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.swssf.impl.processor.output;

import org.apache.commons.codec.binary.Base64;
import org.swssf.ext.*;
import org.swssf.impl.SignaturePartDef;
import org.swssf.impl.algorithms.SignatureAlgorithm;
import org.swssf.impl.algorithms.SignatureAlgorithmFactory;
import org.swssf.impl.util.SignerOutputStream;
import org.swssf.securityEvent.SecurityEvent;
import org.swssf.securityEvent.SignatureValueSecurityEvent;

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
 * @author $Author: giger $
 * @version $Revision: 272 $ $Date: 2010-12-23 14:30:56 +0100 (Thu, 23 Dec 2010) $
 */
public class SignatureEndingOutputProcessor extends AbstractBufferingOutputProcessor {

    private List<SignaturePartDef> signaturePartDefList;

    public SignatureEndingOutputProcessor(SecurityProperties securityProperties, Constants.Action action, SignatureOutputProcessor signatureOutputProcessor) throws WSSecurityException {
        super(securityProperties, action);
        this.getAfterProcessors().add(SignatureOutputProcessor.class.getName());
        this.getAfterProcessors().add(UsernameTokenOutputProcessor.class.getName());
        signaturePartDefList = signatureOutputProcessor.getSignaturePartDefList();
    }

    @Override
    public void doFinal(OutputProcessorChain outputProcessorChain) throws XMLStreamException, WSSecurityException {
        setAppendAfterThisTokenId(outputProcessorChain.getSecurityContext().<String>get(Constants.PROP_APPEND_SIGNATURE_ON_THIS_ID));
        super.doFinal(outputProcessorChain);
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

    protected void processHeaderEvent(OutputProcessorChain outputProcessorChain) throws XMLStreamException, WSSecurityException {

        OutputProcessorChain subOutputProcessorChain = outputProcessorChain.createSubChain(this);

        Map<QName, String> attributes = new HashMap<QName, String>();
        attributes.put(Constants.ATT_NULL_Id, "Signature-" + UUID.randomUUID().toString());
        createStartElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_dsig_Signature, attributes);

        SignatureAlgorithm signatureAlgorithm;

        try {
            signatureAlgorithm = SignatureAlgorithmFactory.getInstance().getSignatureAlgorithm(getSecurityProperties().getSignatureAlgorithm());
        } catch (NoSuchAlgorithmException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_SIGNATURE, e);
        } catch (NoSuchProviderException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "noSecProvider", e);
        }

        String tokenId = outputProcessorChain.getSecurityContext().get(Constants.PROP_USE_THIS_TOKEN_ID_FOR_SIGNATURE);
        if (tokenId == null) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_SIGNATURE);
        }
        SecurityTokenProvider wrappingSecurityTokenProvider = outputProcessorChain.getSecurityContext().getSecurityTokenProvider(tokenId);
        if (wrappingSecurityTokenProvider == null) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_SIGNATURE);
        }
        final SecurityToken wrappingSecurityToken = wrappingSecurityTokenProvider.getSecurityToken(null);
        if (wrappingSecurityToken == null) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_SIGNATURE);
        }

        signatureAlgorithm.engineInitSign(wrappingSecurityToken.getSecretKey(getSecurityProperties().getSignatureAlgorithm()));

        SignedInfoProcessor signedInfoProcessor = new SignedInfoProcessor(getSecurityProperties(), getAction(), signatureAlgorithm);
        subOutputProcessorChain.addProcessor(signedInfoProcessor);

        createStartElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_dsig_SignedInfo, null);

        attributes = new HashMap<QName, String>();
        attributes.put(Constants.ATT_NULL_Algorithm, getSecurityProperties().getSignatureCanonicalizationAlgorithm());
        createStartElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_dsig_CanonicalizationMethod, attributes);
        createEndElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_dsig_CanonicalizationMethod);

        attributes = new HashMap<QName, String>();
        attributes.put(Constants.ATT_NULL_Algorithm, getSecurityProperties().getSignatureAlgorithm());
        createStartElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_dsig_SignatureMethod, attributes);
        createEndElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_dsig_SignatureMethod);

        Iterator<SignaturePartDef> signaturePartDefIterator = signaturePartDefList.iterator();
        while (signaturePartDefIterator.hasNext()) {
            SignaturePartDef signaturePartDef = signaturePartDefIterator.next();
            attributes = new HashMap<QName, String>();
            attributes.put(Constants.ATT_NULL_URI, "#" + signaturePartDef.getSigRefId());
            createStartElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_dsig_Reference, attributes);
            createStartElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_dsig_Transforms, null);

            if (signaturePartDef.getTransformAlgo() != null) {
                attributes = new HashMap<QName, String>();
                attributes.put(Constants.ATT_NULL_Algorithm, signaturePartDef.getTransformAlgo());
                createStartElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_dsig_Transform, attributes);
                createStartElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_wsse_TransformationParameters, null);
                attributes = new HashMap<QName, String>();
                attributes.put(Constants.ATT_NULL_Algorithm, signaturePartDef.getC14nAlgo());
                createStartElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_dsig_CanonicalizationMethod, attributes);
                createEndElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_dsig_CanonicalizationMethod);
                createEndElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_wsse_TransformationParameters);
                createEndElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_dsig_Transform);
            } else {
                attributes = new HashMap<QName, String>();
                attributes.put(Constants.ATT_NULL_Algorithm, signaturePartDef.getC14nAlgo());
                createStartElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_dsig_Transform, attributes);
                createEndElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_dsig_Transform);
            }

            createEndElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_dsig_Transforms);

            attributes = new HashMap<QName, String>();
            attributes.put(Constants.ATT_NULL_Algorithm, getSecurityProperties().getSignatureDigestAlgorithm());
            createStartElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_dsig_DigestMethod, attributes);
            createEndElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_dsig_DigestMethod);
            createStartElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_dsig_DigestValue, null);
            createCharactersAndOutputAsEvent(subOutputProcessorChain, signaturePartDef.getDigestValue());
            createEndElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_dsig_DigestValue);
            createEndElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_dsig_Reference);
        }

        createEndElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_dsig_SignedInfo);
        subOutputProcessorChain.removeProcessor(signedInfoProcessor);

        createStartElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_dsig_SignatureValue, null);
        final byte[] signatureValue = signedInfoProcessor.getSignatureValue();
        createCharactersAndOutputAsEvent(subOutputProcessorChain, new Base64(76, new byte[]{'\n'}).encodeToString(signatureValue));
        createEndElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_dsig_SignatureValue);

        attributes = new HashMap<QName, String>();
        attributes.put(Constants.ATT_NULL_Id, "KeyId-" + UUID.randomUUID().toString());
        createStartElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_dsig_KeyInfo, attributes);
        createSecurityTokenReferenceStructureForSignature(subOutputProcessorChain, wrappingSecurityToken, getSecurityProperties().getSignatureKeyIdentifierType(), getSecurityProperties().isUseSingleCert());
        createEndElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_dsig_KeyInfo);
        createEndElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_dsig_Signature);

        SignatureValueSecurityEvent signatureValueSecurityEvent = new SignatureValueSecurityEvent(SecurityEvent.Event.SignatureValue);
        signatureValueSecurityEvent.setSignatureValue(signatureValue);
        outputProcessorChain.getSecurityContext().registerSecurityEvent(signatureValueSecurityEvent);
    }

    class SignedInfoProcessor extends AbstractOutputProcessor {

        private SignerOutputStream signerOutputStream;
        private OutputStream bufferedSignerOutputStream;
        private Transformer transformer;

        SignedInfoProcessor(SecurityProperties securityProperties, Constants.Action action, SignatureAlgorithm signatureAlgorithm) throws WSSecurityException {
            super(securityProperties, action);
            this.getAfterProcessors().add(SignatureEndingOutputProcessor.class.getName());

            signerOutputStream = new SignerOutputStream(signatureAlgorithm);
            bufferedSignerOutputStream = new BufferedOutputStream(signerOutputStream);

            try {
                transformer = Utils.getTransformer((String) null, this.bufferedSignerOutputStream, getSecurityProperties().getSignatureCanonicalizationAlgorithm());
            } catch (NoSuchMethodException e) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_SIGNATURE, e);
            } catch (InstantiationException e) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_SIGNATURE, e);
            } catch (IllegalAccessException e) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_SIGNATURE, e);
            } catch (InvocationTargetException e) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_SIGNATURE, e);
            }
        }

        public byte[] getSignatureValue() throws WSSecurityException {
            try {
                bufferedSignerOutputStream.close();
                return signerOutputStream.sign();
            } catch (IOException e) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_SIGNATURE, e);
            }
        }

        @Override
        public void processEvent(XMLEvent xmlEvent, OutputProcessorChain outputProcessorChain) throws XMLStreamException, WSSecurityException {
            transformer.transform(xmlEvent);
            outputProcessorChain.processEvent(xmlEvent);
        }
    }
}
