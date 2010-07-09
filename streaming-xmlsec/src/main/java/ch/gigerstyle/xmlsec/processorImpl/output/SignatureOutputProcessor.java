package ch.gigerstyle.xmlsec.processorImpl.output;

import ch.gigerstyle.xmlsec.*;
import ch.gigerstyle.xmlsec.DigestOutputStream;
import ch.gigerstyle.xmlsec.config.JCEAlgorithmMapper;
import ch.gigerstyle.xmlsec.crypto.WSSecurityException;
import org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_secext_1_0.BinarySecurityTokenType;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.*;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.*;

/**
 * User: giger
 * Date: Jun 10, 2010
 * Time: 7:32:56 PM
 * Copyright 2010 Marc Giger gigerstyle@gmx.ch
 * <p/>
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 * <p/>
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * <p/>
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */
public class SignatureOutputProcessor extends AbstractOutputProcessor {

    private List<SecurePart> secureParts;
    private List<SignaturePartDef> signaturePartDefList = new ArrayList<SignaturePartDef>();

    private boolean bstProcessorAdded = false;
    private InternalSignatureOutputProcessor activeInternalSignatureOutputProcessor = null;

    private boolean useSingleCert = true;

    public SignatureOutputProcessor(SecurityProperties securityProperties) throws XMLSecurityException {
        super(securityProperties);
        secureParts = securityProperties.getSignatureSecureParts();
    }

    @Override
    public void processEvent(XMLEvent xmlEvent, OutputProcessorChain outputProcessorChain, SecurityContext securityContext) throws XMLStreamException, XMLSecurityException {
        if (xmlEvent.isStartElement()) {
            StartElement startElement = xmlEvent.asStartElement();

            //avoid double signature when child elements matches too
            if (activeInternalSignatureOutputProcessor == null) {
                for (int i = 0; i < secureParts.size(); i++) {
                    SecurePart securePart = secureParts.get(i);
                    if (securePart.getId() == null) {
                        if (startElement.getName().getLocalPart().equals(securePart.getName())
                                && startElement.getName().getNamespaceURI().equals(securePart.getNamespace())) {

                            logger.debug("Matched securePart for signature");
                            InternalSignatureOutputProcessor internalSignatureOutputProcessor = null;
                            try {
                                SignaturePartDef signaturePartDef = new SignaturePartDef();
                                signaturePartDef.setModifier(SignaturePartDef.Modifier.valueOf(securePart.getModifier()));
                                signaturePartDef.setSigRefId("id-" + UUID.randomUUID().toString());//"EncDataId-1612925417"
                                //signaturePartDef.setKeyId("#" + symmetricKeyId);//#EncKeyId-1483925398
                                //signaturePartDef.setSymmetricKey(symmetricKey);
                                signaturePartDefList.add(signaturePartDef);
                                internalSignatureOutputProcessor = new InternalSignatureOutputProcessor(getSecurityProperties(), signaturePartDef, startElement.getName());

                                List<Namespace> namespaceList = new ArrayList<Namespace>();
                                Iterator<Namespace> namespaceIterator = startElement.getNamespaces();
                                while (namespaceIterator.hasNext()) {
                                    Namespace namespace = namespaceIterator.next();
                                    namespaceList.add(namespace);
                                }
                                namespaceList.add(securityContext.<XMLEventNSAllocator>get("XMLEventNSAllocator").createNamespace(Constants.ATT_wsu_Id.getPrefix(), Constants.ATT_wsu_Id.getNamespaceURI()));

                                List<Attribute> attributeList = new ArrayList<Attribute>();
                                Iterator<Attribute> attributeIterator = startElement.getAttributes();
                                while (attributeIterator.hasNext()) {
                                    Attribute attribute = attributeIterator.next();
                                    attributeList.add(attribute);
                                }
                                attributeList.add(securityContext.<XMLEventNSAllocator>get("XMLEventNSAllocator").createAttribute(Constants.ATT_wsu_Id, signaturePartDef.getSigRefId()));
                                //todo this event should probably be allocated directly and not with our allocator to hold the stack consistent
                                //or also generate the matching endElement...
                                xmlEvent = securityContext.<XMLEventNSAllocator>get("XMLEventNSAllocator").createStartElement(startElement.getName(), namespaceList, attributeList);

                            } catch (NoSuchAlgorithmException e) {
                                throw new XMLSecurityException(e.getMessage(), e);
                            } catch (NoSuchProviderException e) {
                                throw new XMLSecurityException(e.getMessage(), e);
                            }

                            activeInternalSignatureOutputProcessor = internalSignatureOutputProcessor;
                            outputProcessorChain.addProcessor(internalSignatureOutputProcessor);
                            break;
                        }
                    }
                }
            }
        }
        outputProcessorChain.processEvent(xmlEvent);
    }

    @Override
    public void processHeaderEvent(XMLEvent xmlEvent, OutputProcessorChain outputProcessorChain, SecurityContext securityContext) throws XMLStreamException, XMLSecurityException {

        outputProcessorChain.processHeaderEvent(xmlEvent);

        if (xmlEvent.isStartElement()) {
            StartElement startElement = xmlEvent.asStartElement();
            if (startElement.getName().equals(Constants.TAG_wsse_Security)) {

                OutputProcessorChain subOutputProcessorChain = outputProcessorChain.createSubChain(this);

                String alias = getSecurityProperties().getSignatureUser();

                X509Certificate[] x509Certificates;
                try {
                    x509Certificates = getSecurityProperties().getSignatureCrypto().getCertificates(alias);
                } catch (WSSecurityException e) {
                    throw new XMLSecurityException(e);
                }
                if (x509Certificates == null || x509Certificates.length == 0) {
                    throw new XMLSecurityException("noUserCertsFound");
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
                    createStartElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_wsse_BinarySecurityToken, attributes);
                    try {
                        createCharactersAndOutputAsHeaderEvent(subOutputProcessorChain, Base64.encode(x509Certificates[0].getEncoded()));
                    } catch (CertificateEncodingException e) {
                        throw new XMLSecurityException(e);
                    }
                    createEndElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_wsse_BinarySecurityToken);
                }

                Map<QName, String> attributes = new HashMap<QName, String>();
                attributes.put(Constants.ATT_NULL_Id, "Signature-" + UUID.randomUUID().toString());
                createStartElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_dsig_Signature, attributes);

                WSPasswordCallback pwCb = new WSPasswordCallback(alias, WSPasswordCallback.SIGNATURE);
                try {
                    Callback[] callbacks = new Callback[]{pwCb};
                    getSecurityProperties().getCallbackHandler().handle(callbacks);
                } catch (IOException e) {
                    throw new XMLSecurityException("noPassword " + alias, e);
                } catch (UnsupportedCallbackException e) {
                    throw new XMLSecurityException("noPassword " + alias, e);
                }
                String password = pwCb.getPassword();
                if (password == null) {
                    throw new XMLSecurityException("noPassword " + alias);
                }

                String signatureAlgorithm = JCEAlgorithmMapper.translateURItoJCEID(getSecurityProperties().getSignatureAlgorithm());
                Signature signature = null;
                try {
                    signature = Signature.getInstance(signatureAlgorithm, "BC");
                } catch (NoSuchAlgorithmException e) {
                    throw new XMLSecurityException(e);
                } catch (NoSuchProviderException e) {
                    throw new XMLSecurityException(e);
                }

                try {
                    signature.initSign(
                            getSecurityProperties().getSignatureCrypto().getPrivateKey(
                                    alias,
                                    password));
                } catch (Exception e) {
                    throw new XMLSecurityException(e);
                }

                SignedInfoProcessor signedInfoProcessor = new SignedInfoProcessor(getSecurityProperties(), signature);
                subOutputProcessorChain.addProcessor(signedInfoProcessor);

                createStartElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_dsig_SignedInfo, null);

                attributes = new HashMap<QName, String>();
                attributes.put(Constants.ATT_NULL_Algorithm, getSecurityProperties().getSignatureCanonicalizationAlgorithm());
                createStartElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_dsig_CanonicalizationMethod, attributes);
                createEndElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_dsig_CanonicalizationMethod);

                attributes = new HashMap<QName, String>();
                attributes.put(Constants.ATT_NULL_Algorithm, getSecurityProperties().getSignatureAlgorithm());
                createStartElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_dsig_SignatureMethod, attributes);
                createEndElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_dsig_SignatureMethod);

                for (int i = 0; i < signaturePartDefList.size(); i++) {
                    SignaturePartDef signaturePartDef = signaturePartDefList.get(i);
                    attributes = new HashMap<QName, String>();
                    attributes.put(Constants.ATT_NULL_URI, "#" + signaturePartDef.getSigRefId());
                    createStartElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_dsig_Reference, attributes);
                    createStartElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_dsig_Transforms, null);

                    attributes = new HashMap<QName, String>();
                    attributes.put(Constants.ATT_NULL_Algorithm, getSecurityProperties().getSignatureCanonicalizationAlgorithm());
                    createStartElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_dsig_Transform, attributes);
                    createEndElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_dsig_Transform);

                    createEndElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_dsig_Transforms);

                    attributes = new HashMap<QName, String>();
                    attributes.put(Constants.ATT_NULL_Algorithm, getSecurityProperties().getSignatureDigestAlgorithm());
                    createStartElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_dsig_DigestMethod, attributes);
                    createEndElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_dsig_DigestMethod);
                    createStartElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_dsig_DigestValue, null);
                    createCharactersAndOutputAsHeaderEvent(subOutputProcessorChain, signaturePartDef.getDigestValue());
                    createEndElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_dsig_DigestValue);
                    createEndElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_dsig_Reference);
                }

                createEndElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_dsig_SignedInfo);
                subOutputProcessorChain.removeProcessor(signedInfoProcessor);
                createStartElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_dsig_SignatureValue, null);
                createCharactersAndOutputAsHeaderEvent(subOutputProcessorChain, Base64.encode(signedInfoProcessor.getSignatureValue()));
                createEndElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_dsig_SignatureValue);

                attributes = new HashMap<QName, String>();
                attributes.put(Constants.ATT_NULL_Id, "KeyId-" + UUID.randomUUID().toString());
                createStartElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_dsig_KeyInfo, attributes);

                attributes = new HashMap<QName, String>();
                attributes.put(Constants.ATT_wsu_Id, "STRId-" + UUID.randomUUID().toString());
                createStartElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_wsse_SecurityTokenReference, attributes);

                if (getSecurityProperties().getSignatureKeyIdentifierType() == Constants.KeyIdentifierType.ISSUER_SERIAL) {

                    createStartElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_dsig_X509Data, null);
                    createStartElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_dsig_X509IssuerSerial, null);
                    createStartElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_dsig_X509IssuerName, null);
                    createCharactersAndOutputAsHeaderEvent(subOutputProcessorChain, RFC2253Parser.normalize(x509Certificates[0].getIssuerDN().getName()));
                    createEndElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_dsig_X509IssuerName);
                    createStartElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_dsig_X509SerialNumber, null);
                    createCharactersAndOutputAsHeaderEvent(subOutputProcessorChain, x509Certificates[0].getSerialNumber().toString());
                    createEndElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_dsig_X509SerialNumber);
                    createEndElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_dsig_X509IssuerSerial);
                    createEndElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_dsig_X509Data);
                } else if (getSecurityProperties().getSignatureKeyIdentifierType() == Constants.KeyIdentifierType.SKI_KEY_IDENTIFIER) {
                    // As per the 1.1 specification, SKI can only be used for a V3 certificate
                    if (x509Certificates[0].getVersion() != 3) {
                        throw new XMLSecurityException("invalidCertForSKI");
                    }

                    attributes = new HashMap<QName, String>();
                    attributes.put(Constants.ATT_NULL_EncodingType, Constants.SOAPMESSAGE_NS10_BASE64_ENCODING);
                    attributes.put(Constants.ATT_NULL_ValueType, Constants.NS_X509SubjectKeyIdentifier);
                    createStartElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_wsse_KeyIdentifier, attributes);
                    try {
                        byte data[] = getSecurityProperties().getSignatureCrypto().getSKIBytesFromCert(x509Certificates[0]);
                        createCharactersAndOutputAsHeaderEvent(subOutputProcessorChain, Base64.encode(data));
                    } catch (WSSecurityException e) {
                        throw new XMLSecurityException(e);
                    }
                    createEndElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_wsse_KeyIdentifier);
                } else if (getSecurityProperties().getSignatureKeyIdentifierType() == Constants.KeyIdentifierType.X509_KEY_IDENTIFIER) {

                    attributes = new HashMap<QName, String>();
                    attributes.put(Constants.ATT_NULL_EncodingType, Constants.SOAPMESSAGE_NS10_BASE64_ENCODING);
                    attributes.put(Constants.ATT_NULL_ValueType, Constants.NS_X509_V3_TYPE);
                    createStartElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_wsse_KeyIdentifier, attributes);
                    try {
                        createCharactersAndOutputAsHeaderEvent(subOutputProcessorChain, Base64.encode(x509Certificates[0].getEncoded()));
                    } catch (CertificateEncodingException e) {
                        throw new XMLSecurityException(e);
                    }
                    createEndElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_wsse_KeyIdentifier);
                } else if (getSecurityProperties().getSignatureKeyIdentifierType() == Constants.KeyIdentifierType.THUMBPRINT_IDENTIFIER) {

                    attributes = new HashMap<QName, String>();
                    attributes.put(Constants.ATT_NULL_EncodingType, Constants.SOAPMESSAGE_NS10_BASE64_ENCODING);
                    attributes.put(Constants.ATT_NULL_ValueType, Constants.NS_THUMBPRINT);
                    createStartElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_wsse_KeyIdentifier, attributes);
                    try {
                        MessageDigest sha = null;
                        sha = MessageDigest.getInstance("SHA-1");
                        sha.reset();
                        sha.update(x509Certificates[0].getEncoded());
                        byte[] data = sha.digest();

                        createCharactersAndOutputAsHeaderEvent(subOutputProcessorChain, Base64.encode(data));
                    } catch (CertificateEncodingException e) {
                        throw new XMLSecurityException(e);
                    } catch (NoSuchAlgorithmException e) {
                        throw new XMLSecurityException(e);
                    }
                    createEndElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_wsse_KeyIdentifier);
                } else if (getSecurityProperties().getSignatureKeyIdentifierType() == Constants.KeyIdentifierType.BST_EMBEDDED) {

                    attributes = new HashMap<QName, String>();
                    attributes.put(Constants.ATT_NULL_URI, "#" + certUri);
                    if (useSingleCert) {
                        attributes.put(Constants.ATT_NULL_ValueType, Constants.NS_X509_V3_TYPE);
                    } else {
                        attributes.put(Constants.ATT_NULL_ValueType, Constants.NS_X509PKIPathv1);
                    }
                    createStartElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_wsse_Reference, attributes);

                    //todo probably we can reuse BinarySecurityTokenOutputProcessor??
                    attributes = new HashMap<QName, String>();
                    attributes.put(Constants.ATT_NULL_EncodingType, Constants.SOAPMESSAGE_NS10_BASE64_ENCODING);
                    if (useSingleCert) {
                        attributes.put(Constants.ATT_NULL_ValueType, Constants.NS_X509_V3_TYPE);
                    } else {
                        attributes.put(Constants.ATT_NULL_ValueType, Constants.NS_X509PKIPathv1);
                    }
                    attributes.put(Constants.ATT_wsu_Id, certUri);
                    createStartElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_wsse_BinarySecurityToken, attributes);
                    try {
                        if (useSingleCert) {
                            createCharactersAndOutputAsHeaderEvent(subOutputProcessorChain, Base64.encode(x509Certificates[0].getEncoded()));
                        } else {
                            createCharactersAndOutputAsHeaderEvent(subOutputProcessorChain, Base64.encode(getSecurityProperties().getSignatureCrypto().getCertificateData(false, x509Certificates)));
                        }
                    } catch (CertificateEncodingException e) {
                        throw new XMLSecurityException(e);
                    } catch (WSSecurityException e) {
                        throw new XMLSecurityException(e);
                    }
                    createEndElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_wsse_BinarySecurityToken);
                    createEndElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_wsse_Reference);
                } else if (getSecurityProperties().getSignatureKeyIdentifierType() == Constants.KeyIdentifierType.BST_DIRECT_REFERENCE) {

                    attributes = new HashMap<QName, String>();
                    attributes.put(Constants.ATT_NULL_URI, "#" + certUri);
                    attributes.put(Constants.ATT_NULL_ValueType, referencedBinarySecurityTokenType.getValueType());
                    createStartElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_wsse_Reference, attributes);
                    createEndElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_wsse_Reference);
                } else {
                    throw new XMLSecurityException("Unsupported SecurityToken: " + getSecurityProperties().getSignatureKeyIdentifierType().name());
                }

                createEndElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_wsse_SecurityTokenReference);
                createEndElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_dsig_KeyInfo);
                createEndElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_dsig_Signature);

                outputProcessorChain.removeProcessor(this);

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
        }
    }

    class InternalSignatureOutputProcessor extends AbstractOutputProcessor {

        private SignaturePartDef signaturePartDef;
        private QName startElement;
        private int elementCounter = 0;

        private OutputStream bufferedDigestOutputStream;
        private DigestOutputStream digestOutputStream;
        private List<Transformer> transformers = new ArrayList<Transformer>();

        InternalSignatureOutputProcessor(SecurityProperties securityProperties, SignaturePartDef signaturePartDef, QName startElement) throws XMLSecurityException, NoSuchProviderException, NoSuchAlgorithmException {
            super(securityProperties);
            this.signaturePartDef = signaturePartDef;
            this.startElement = startElement;

            String algorithmID = JCEAlgorithmMapper.translateURItoJCEID(getSecurityProperties().getSignatureDigestAlgorithm());
            MessageDigest messageDigest = MessageDigest.getInstance(algorithmID, "BC");
            this.digestOutputStream = new DigestOutputStream(messageDigest);
            this.bufferedDigestOutputStream = new BufferedOutputStream(digestOutputStream);

            transformers.add(new Canonicalizer20010315ExclOmitCommentsTransformer(null));
        }

        @Override
        public void processEvent(XMLEvent xmlEvent, OutputProcessorChain outputProcessorChain, SecurityContext securityContext) throws XMLStreamException, XMLSecurityException {

            for (int i = 0; i < transformers.size(); i++) {
                Transformer transformer = transformers.get(i);
                transformer.transform(xmlEvent, this.bufferedDigestOutputStream);
            }

            if (xmlEvent.isStartElement()) {
                elementCounter++;
            } else if (xmlEvent.isEndElement()) {
                elementCounter--;

                EndElement endElement = xmlEvent.asEndElement();

                if (endElement.getName().equals(this.startElement) && elementCounter == 0) {
                    try {
                        bufferedDigestOutputStream.close();
                    } catch (IOException e) {
                        throw new XMLSecurityException(e);
                    }
                    String calculatedDigest = new String(org.bouncycastle.util.encoders.Base64.encode(this.digestOutputStream.getDigestValue()));
                    logger.debug("Calculated Digest: " + calculatedDigest);
                    signaturePartDef.setDigestValue(calculatedDigest);

                    outputProcessorChain.removeProcessor(this);
                    //from now on signature is possible again
                    activeInternalSignatureOutputProcessor = null;
                }
            }
            outputProcessorChain.processEvent(xmlEvent);
        }

        @Override
        public void processHeaderEvent(XMLEvent xmlEvent, OutputProcessorChain outputProcessorChain, SecurityContext securityContext) throws XMLStreamException, XMLSecurityException {
            outputProcessorChain.processHeaderEvent(xmlEvent);
        }
    }

    class SignedInfoProcessor extends AbstractOutputProcessor {

        private SignerOutputStream signerOutputStream;
        private OutputStream bufferedSignerOutputStream;
        private Canonicalizer20010315Transformer canonicalizer20010315Transformer;

        SignedInfoProcessor(SecurityProperties securityProperties, Signature signature) throws XMLSecurityException {
            super(securityProperties);

            signerOutputStream = new SignerOutputStream(signature);
            bufferedSignerOutputStream = new BufferedOutputStream(signerOutputStream);
            canonicalizer20010315Transformer = new Canonicalizer20010315ExclOmitCommentsTransformer(null);
        }

        public byte[] getSignatureValue() throws XMLSecurityException {
            try {
                bufferedSignerOutputStream.close();
                return signerOutputStream.sign();
            } catch (SignatureException e) {
                throw new XMLSecurityException(e);
            } catch (IOException e) {
                throw new XMLSecurityException(e);
            }
        }

        @Override
        public void processEvent(XMLEvent xmlEvent, OutputProcessorChain outputProcessorChain, SecurityContext securityContext) throws XMLStreamException, XMLSecurityException {
            outputProcessorChain.processEvent(xmlEvent);
        }

        @Override
        public void processHeaderEvent(XMLEvent xmlEvent, OutputProcessorChain outputProcessorChain, SecurityContext securityContext) throws XMLStreamException, XMLSecurityException {
            canonicalizer20010315Transformer.transform(xmlEvent, bufferedSignerOutputStream);
            outputProcessorChain.processHeaderEvent(xmlEvent);
        }
    }
}
