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
import org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_secext_1_0.BinarySecurityTokenType;
import org.swssf.config.JCEAlgorithmMapper;
import org.swssf.ext.*;
import org.swssf.impl.SignaturePartDef;
import org.swssf.impl.transformer.canonicalizer.Canonicalizer20010315ExclOmitCommentsTransformer;
import org.swssf.impl.transformer.canonicalizer.Canonicalizer20010315Transformer;
import org.swssf.impl.util.RFC2253Parser;
import org.swssf.impl.util.SignerOutputStream;
import org.xmlsecurity.ns.configuration.AlgorithmType;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.*;

/**
 * @author $Author: giger $
 * @version $Revision: 272 $ $Date: 2010-12-23 14:30:56 +0100 (Thu, 23 Dec 2010) $
 */
public class SignatureEndingOutputProcessor extends AbstractOutputProcessor {

    private List<SignaturePartDef> signaturePartDefList;

    private boolean useSingleCert = true;

    //todo try to use a hint how much elements are expected from other processors? 
    //private List<XMLEvent> xmlEventBuffer = new ArrayList<XMLEvent>(100);
    private ArrayDeque<XMLEvent> xmlEventBuffer = new ArrayDeque<XMLEvent>();

    public SignatureEndingOutputProcessor(SecurityProperties securityProperties, SignatureOutputProcessor signatureOutputProcessor) throws WSSecurityException {
        super(securityProperties);
        this.getAfterProcessors().add(SignatureOutputProcessor.class.getName());
        signaturePartDefList = signatureOutputProcessor.getSignaturePartDefList();
        //todo throw exception when list is empty?
    }

    @Override
    public void processEvent(XMLEvent xmlEvent, OutputProcessorChain outputProcessorChain) throws XMLStreamException, WSSecurityException {
        xmlEventBuffer.push(xmlEvent);
    }

    @Override
    public void doFinal(OutputProcessorChain outputProcessorChain) throws XMLStreamException, WSSecurityException {

        OutputProcessorChain subOutputProcessorChain = outputProcessorChain.createSubChain(this);

        Iterator<XMLEvent> xmlEventIterator = xmlEventBuffer.descendingIterator();
        while (xmlEventIterator.hasNext()) {
            XMLEvent xmlEvent = xmlEventIterator.next();
            if (xmlEvent.isStartElement()) {
                StartElement startElement = xmlEvent.asStartElement();
                if (startElement.getName().equals(Constants.TAG_wsse_Security)) {
                    subOutputProcessorChain.reset();
                    subOutputProcessorChain.processEvent(xmlEvent);
                    processHeaderEvent(subOutputProcessorChain);
                    continue;
                }
            }
            subOutputProcessorChain.reset();
            subOutputProcessorChain.processEvent(xmlEvent);
        }
        subOutputProcessorChain.reset();
        subOutputProcessorChain.doFinal();
        subOutputProcessorChain.removeProcessor(this);
    }

    private void processHeaderEvent(OutputProcessorChain outputProcessorChain) throws XMLStreamException, WSSecurityException {

        OutputProcessorChain subOutputProcessorChain = outputProcessorChain.createSubChain(this);

        String alias = getSecurityProperties().getSignatureUser();

        X509Certificate[] x509Certificates;
        try {
            x509Certificates = getSecurityProperties().getSignatureCrypto().getCertificates(alias);
        } catch (org.swssf.crypto.WSSecurityException e) {
            throw new WSSecurityException(e);
        }
        if (x509Certificates == null || x509Certificates.length == 0) {
            throw new WSSecurityException("noUserCertsFound");
        }

        String certUri = "CertId-" + UUID.randomUUID().toString();
        BinarySecurityTokenType referencedBinarySecurityTokenType = null;
        if (getSecurityProperties().getSignatureKeyIdentifierType() == Constants.KeyIdentifierType.BST_DIRECT_REFERENCE) {
            referencedBinarySecurityTokenType = new BinarySecurityTokenType();
            referencedBinarySecurityTokenType.setEncodingType(Constants.SOAPMESSAGE_NS10_BASE64_ENCODING);
            referencedBinarySecurityTokenType.setValueType(Constants.NS_X509_V3_TYPE);
            referencedBinarySecurityTokenType.setId(certUri);

            Map<QName, String> attributes = new HashMap<QName, String>();
            attributes.put(Constants.ATT_NULL_EncodingType, referencedBinarySecurityTokenType.getEncodingType());
            attributes.put(Constants.ATT_NULL_ValueType, referencedBinarySecurityTokenType.getValueType());
            attributes.put(Constants.ATT_wsu_Id, referencedBinarySecurityTokenType.getId());
            createStartElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_wsse_BinarySecurityToken, attributes);
            try {
                createCharactersAndOutputAsEvent(subOutputProcessorChain, Base64.encodeBase64String(x509Certificates[0].getEncoded()));
            } catch (CertificateEncodingException e) {
                throw new WSSecurityException(e);
            }
            createEndElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_wsse_BinarySecurityToken);
        }

        Map<QName, String> attributes = new HashMap<QName, String>();
        attributes.put(Constants.ATT_NULL_Id, "Signature-" + UUID.randomUUID().toString());
        createStartElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_dsig_Signature, attributes);

        WSPasswordCallback pwCb = new WSPasswordCallback(alias, WSPasswordCallback.SIGNATURE);
        try {
            Callback[] callbacks = new Callback[]{pwCb};
            getSecurityProperties().getCallbackHandler().handle(callbacks);
        } catch (IOException e) {
            throw new WSSecurityException("noPassword " + alias, e);
        } catch (UnsupportedCallbackException e) {
            throw new WSSecurityException("noPassword " + alias, e);
        }
        String password = pwCb.getPassword();
        if (password == null) {
            throw new WSSecurityException("noPassword " + alias);
        }

        AlgorithmType signatureAlgorithm = JCEAlgorithmMapper.getAlgorithmMapping(getSecurityProperties().getSignatureAlgorithm());
        Signature signature = null;
        try {
            signature = Signature.getInstance(signatureAlgorithm.getJCEName(), signatureAlgorithm.getJCEProvider());
        } catch (NoSuchAlgorithmException e) {
            throw new WSSecurityException(e);
        } catch (NoSuchProviderException e) {
            throw new WSSecurityException(e);
        }

        try {
            signature.initSign(
                    getSecurityProperties().getSignatureCrypto().getPrivateKey(
                            alias,
                            password));
        } catch (Exception e) {
            throw new WSSecurityException(e);
        }

        SignedInfoProcessor signedInfoProcessor = new SignedInfoProcessor(getSecurityProperties(), signature);
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

            attributes = new HashMap<QName, String>();
            attributes.put(Constants.ATT_NULL_Algorithm, getSecurityProperties().getSignatureCanonicalizationAlgorithm());
            createStartElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_dsig_Transform, attributes);
            createEndElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_dsig_Transform);

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
        createCharactersAndOutputAsEvent(subOutputProcessorChain, Base64.encodeBase64String(signedInfoProcessor.getSignatureValue()));
        createEndElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_dsig_SignatureValue);

        attributes = new HashMap<QName, String>();
        attributes.put(Constants.ATT_NULL_Id, "KeyId-" + UUID.randomUUID().toString());
        createStartElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_dsig_KeyInfo, attributes);

        attributes = new HashMap<QName, String>();
        attributes.put(Constants.ATT_wsu_Id, "STRId-" + UUID.randomUUID().toString());
        createStartElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_wsse_SecurityTokenReference, attributes);

        if (getSecurityProperties().getSignatureKeyIdentifierType() == Constants.KeyIdentifierType.ISSUER_SERIAL) {

            createStartElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_dsig_X509Data, null);
            createStartElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_dsig_X509IssuerSerial, null);
            createStartElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_dsig_X509IssuerName, null);
            createCharactersAndOutputAsEvent(subOutputProcessorChain, RFC2253Parser.normalize(x509Certificates[0].getIssuerDN().getName()));
            createEndElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_dsig_X509IssuerName);
            createStartElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_dsig_X509SerialNumber, null);
            createCharactersAndOutputAsEvent(subOutputProcessorChain, x509Certificates[0].getSerialNumber().toString());
            createEndElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_dsig_X509SerialNumber);
            createEndElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_dsig_X509IssuerSerial);
            createEndElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_dsig_X509Data);
        } else if (getSecurityProperties().getSignatureKeyIdentifierType() == Constants.KeyIdentifierType.SKI_KEY_IDENTIFIER) {
            // As per the 1.1 specification, SKI can only be used for a V3 certificate
            if (x509Certificates[0].getVersion() != 3) {
                throw new WSSecurityException("invalidCertForSKI");
            }

            attributes = new HashMap<QName, String>();
            attributes.put(Constants.ATT_NULL_EncodingType, Constants.SOAPMESSAGE_NS10_BASE64_ENCODING);
            attributes.put(Constants.ATT_NULL_ValueType, Constants.NS_X509SubjectKeyIdentifier);
            createStartElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_wsse_KeyIdentifier, attributes);
            try {
                byte data[] = getSecurityProperties().getSignatureCrypto().getSKIBytesFromCert(x509Certificates[0]);
                createCharactersAndOutputAsEvent(subOutputProcessorChain, Base64.encodeBase64String(data));
            } catch (org.swssf.crypto.WSSecurityException e) {
                throw new WSSecurityException(e);
            }
            createEndElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_wsse_KeyIdentifier);
        } else if (getSecurityProperties().getSignatureKeyIdentifierType() == Constants.KeyIdentifierType.X509_KEY_IDENTIFIER) {

            attributes = new HashMap<QName, String>();
            attributes.put(Constants.ATT_NULL_EncodingType, Constants.SOAPMESSAGE_NS10_BASE64_ENCODING);
            attributes.put(Constants.ATT_NULL_ValueType, Constants.NS_X509_V3_TYPE);
            createStartElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_wsse_KeyIdentifier, attributes);
            try {
                createCharactersAndOutputAsEvent(subOutputProcessorChain, Base64.encodeBase64String(x509Certificates[0].getEncoded()));
            } catch (CertificateEncodingException e) {
                throw new WSSecurityException(e);
            }
            createEndElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_wsse_KeyIdentifier);
        } else if (getSecurityProperties().getSignatureKeyIdentifierType() == Constants.KeyIdentifierType.THUMBPRINT_IDENTIFIER) {

            attributes = new HashMap<QName, String>();
            attributes.put(Constants.ATT_NULL_EncodingType, Constants.SOAPMESSAGE_NS10_BASE64_ENCODING);
            attributes.put(Constants.ATT_NULL_ValueType, Constants.NS_THUMBPRINT);
            createStartElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_wsse_KeyIdentifier, attributes);
            try {
                MessageDigest sha = null;
                sha = MessageDigest.getInstance("SHA-1");
                sha.reset();
                sha.update(x509Certificates[0].getEncoded());
                byte[] data = sha.digest();

                createCharactersAndOutputAsEvent(subOutputProcessorChain, Base64.encodeBase64String(data));
            } catch (CertificateEncodingException e) {
                throw new WSSecurityException(e);
            } catch (NoSuchAlgorithmException e) {
                throw new WSSecurityException(e);
            }
            createEndElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_wsse_KeyIdentifier);
        } else if (getSecurityProperties().getSignatureKeyIdentifierType() == Constants.KeyIdentifierType.BST_EMBEDDED) {

            attributes = new HashMap<QName, String>();
            attributes.put(Constants.ATT_NULL_URI, "#" + certUri);
            if (useSingleCert) {
                attributes.put(Constants.ATT_NULL_ValueType, Constants.NS_X509_V3_TYPE);
            } else {
                attributes.put(Constants.ATT_NULL_ValueType, Constants.NS_X509PKIPathv1);
            }
            createStartElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_wsse_Reference, attributes);

            //todo probably we can reuse BinarySecurityTokenOutputProcessor??
            attributes = new HashMap<QName, String>();
            attributes.put(Constants.ATT_NULL_EncodingType, Constants.SOAPMESSAGE_NS10_BASE64_ENCODING);
            if (useSingleCert) {
                attributes.put(Constants.ATT_NULL_ValueType, Constants.NS_X509_V3_TYPE);
            } else {
                attributes.put(Constants.ATT_NULL_ValueType, Constants.NS_X509PKIPathv1);
            }
            attributes.put(Constants.ATT_wsu_Id, certUri);
            createStartElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_wsse_BinarySecurityToken, attributes);
            try {
                if (useSingleCert) {
                    createCharactersAndOutputAsEvent(subOutputProcessorChain, Base64.encodeBase64String(x509Certificates[0].getEncoded()));
                } else {
                    createCharactersAndOutputAsEvent(subOutputProcessorChain, Base64.encodeBase64String(getSecurityProperties().getSignatureCrypto().getCertificateData(false, x509Certificates)));
                }
            } catch (CertificateEncodingException e) {
                throw new WSSecurityException(e);
            } catch (org.swssf.crypto.WSSecurityException e) {
                throw new WSSecurityException(e);
            }
            createEndElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_wsse_BinarySecurityToken);
            createEndElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_wsse_Reference);
        } else if (getSecurityProperties().getSignatureKeyIdentifierType() == Constants.KeyIdentifierType.BST_DIRECT_REFERENCE) {

            attributes = new HashMap<QName, String>();
            attributes.put(Constants.ATT_NULL_URI, "#" + certUri);
            attributes.put(Constants.ATT_NULL_ValueType, referencedBinarySecurityTokenType.getValueType());
            createStartElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_wsse_Reference, attributes);
            createEndElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_wsse_Reference);
        } else {
            throw new WSSecurityException("Unsupported SecurityToken: " + getSecurityProperties().getSignatureKeyIdentifierType().name());
        }

        createEndElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_wsse_SecurityTokenReference);
        createEndElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_dsig_KeyInfo);
        createEndElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_dsig_Signature);

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
    }

    class SignedInfoProcessor extends AbstractOutputProcessor {

        private SignerOutputStream signerOutputStream;
        private OutputStream bufferedSignerOutputStream;
        private Canonicalizer20010315Transformer canonicalizer20010315Transformer;

        SignedInfoProcessor(SecurityProperties securityProperties, Signature signature) throws WSSecurityException {
            super(securityProperties);
            this.getAfterProcessors().add(SignatureEndingOutputProcessor.class.getName());

            signerOutputStream = new SignerOutputStream(signature);
            bufferedSignerOutputStream = new BufferedOutputStream(signerOutputStream);
            canonicalizer20010315Transformer = new Canonicalizer20010315ExclOmitCommentsTransformer(null);
        }

        public byte[] getSignatureValue() throws WSSecurityException {
            try {
                bufferedSignerOutputStream.close();
                return signerOutputStream.sign();
            } catch (SignatureException e) {
                throw new WSSecurityException(e);
            } catch (IOException e) {
                throw new WSSecurityException(e);
            }
        }

        @Override
        public void processEvent(XMLEvent xmlEvent, OutputProcessorChain outputProcessorChain) throws XMLStreamException, WSSecurityException {
            canonicalizer20010315Transformer.transform(xmlEvent, bufferedSignerOutputStream);
            outputProcessorChain.processEvent(xmlEvent);
        }
    }
}