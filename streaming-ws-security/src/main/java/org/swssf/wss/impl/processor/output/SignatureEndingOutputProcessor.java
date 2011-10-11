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
package org.swssf.wss.impl.processor.output;

import org.apache.commons.codec.binary.Base64;
import org.swssf.wss.ext.*;
import org.swssf.wss.securityEvent.SecurityEvent;
import org.swssf.wss.securityEvent.SignatureValueSecurityEvent;
import org.swssf.xmlsec.ext.OutputProcessorChain;
import org.swssf.xmlsec.ext.SecurityToken;
import org.swssf.xmlsec.ext.XMLSecurityConstants;
import org.swssf.xmlsec.ext.XMLSecurityException;
import org.swssf.xmlsec.impl.SignaturePartDef;
import org.swssf.xmlsec.impl.algorithms.SignatureAlgorithm;
import org.swssf.xmlsec.impl.processor.output.AbstractSignatureEndingOutputProcessor;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.Attribute;
import javax.xml.stream.events.EndElement;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class SignatureEndingOutputProcessor extends AbstractSignatureEndingOutputProcessor {

    private SignedInfoProcessor signedInfoProcessor = null;

    public SignatureEndingOutputProcessor(WSSSecurityProperties securityProperties, XMLSecurityConstants.Action action, org.swssf.wss.impl.processor.output.SignatureOutputProcessor signatureOutputProcessor) throws XMLSecurityException {
        super(securityProperties, action, signatureOutputProcessor);
        this.getAfterProcessors().add(org.swssf.wss.impl.processor.output.SignatureOutputProcessor.class.getName());
        this.getAfterProcessors().add(UsernameTokenOutputProcessor.class.getName());
    }

    @Override
    public void doFinal(OutputProcessorChain outputProcessorChain) throws XMLStreamException, XMLSecurityException {
        setAppendAfterThisTokenId(outputProcessorChain.getSecurityContext().<String>get(WSSConstants.PROP_APPEND_SIGNATURE_ON_THIS_ID));

        //todo replace this and in EncryptEndingOutputProcessor with a common method somewhere
        OutputProcessorChain subOutputProcessorChain = outputProcessorChain.createSubChain(this);

        //loop until we reach our security header and set flag
        Iterator<XMLEvent> xmlEventIterator = getXmlEventBuffer().descendingIterator();
        while (xmlEventIterator.hasNext()) {
            XMLEvent xmlEvent = xmlEventIterator.next();
            if (xmlEvent.isStartElement()) {
                StartElement startElement = xmlEvent.asStartElement();
                if (startElement.getName().equals(WSSConstants.TAG_wsse_Security)
                        && WSSUtils.isResponsibleActorOrRole(
                        startElement,
                        ((WSSDocumentContext) subOutputProcessorChain.getDocumentContext()).getSOAPMessageVersionNamespace(),
                        ((WSSSecurityProperties) getSecurityProperties()).getActor())) {
                    ((WSSDocumentContext) subOutputProcessorChain.getDocumentContext()).setInSecurityHeader(true);
                    subOutputProcessorChain.reset();
                    subOutputProcessorChain.processEvent(xmlEvent);
                    break;
                }
            }
            subOutputProcessorChain.reset();
            subOutputProcessorChain.processEvent(xmlEvent);
        }

        //append current header
        if (getAppendAfterThisTokenId() == null) {
            processHeaderEvent(subOutputProcessorChain);
        } else {
            //we have a dependent token. so we have to append the current header after the token
            boolean found = false;
            while (xmlEventIterator.hasNext() && !found) {
                XMLEvent xmlEvent = xmlEventIterator.next();

                subOutputProcessorChain.reset();
                subOutputProcessorChain.processEvent(xmlEvent);

                //search for an element with a matching wsu:Id. this is our token
                if (xmlEvent.isStartElement()) {
                    StartElement startElement = xmlEvent.asStartElement();
                    QName matchingElementName;

                    @SuppressWarnings("unchecked")
                    Iterator<Attribute> attributeIterator = startElement.getAttributes();
                    while (attributeIterator.hasNext() && !found) {
                        Attribute attribute = attributeIterator.next();
                        final QName attributeName = attribute.getName();
                        final String attributeValue = attribute.getValue();
                        if ((WSSConstants.ATT_wsu_Id.equals(attributeName) && getAppendAfterThisTokenId().equals(attributeValue))
                                || (WSSConstants.ATT_NULL_Id.equals(attributeName) && getAppendAfterThisTokenId().equals(attributeValue))
                                || (WSSConstants.ATT_NULL_AssertionID.equals(attributeName) && getAppendAfterThisTokenId().equals(attributeValue))
                                || (WSSConstants.ATT_NULL_ID.equals(attributeName) && getAppendAfterThisTokenId().endsWith(attributeValue))) {
                            matchingElementName = startElement.getName();
                            //we found the token and...
                            int level = 0;
                            while (xmlEventIterator.hasNext() && !found) {
                                xmlEvent = xmlEventIterator.next();

                                subOutputProcessorChain.reset();
                                subOutputProcessorChain.processEvent(xmlEvent);

                                //loop until we reach the token end element
                                if (xmlEvent.isEndElement()) {
                                    EndElement endElement = xmlEvent.asEndElement();
                                    if (level == 0 && endElement.getName().equals(matchingElementName)) {
                                        found = true;
                                        //output now the current header
                                        processHeaderEvent(subOutputProcessorChain);
                                    }
                                    level--;
                                } else if (xmlEvent.isStartElement()) {
                                    level++;
                                }
                            }
                        }
                    }
                }
            }
        }
        //loop until our security header end element and unset the flag
        while (xmlEventIterator.hasNext()) {
            XMLEvent xmlEvent = xmlEventIterator.next();
            if (xmlEvent.isEndElement()) {
                EndElement endElement = xmlEvent.asEndElement();
                if (endElement.getName().equals(WSSConstants.TAG_wsse_Security)) {
                    ((WSSDocumentContext) subOutputProcessorChain.getDocumentContext()).setInSecurityHeader(false);
                    subOutputProcessorChain.reset();
                    subOutputProcessorChain.processEvent(xmlEvent);
                    break;
                }
            }
            subOutputProcessorChain.reset();
            subOutputProcessorChain.processEvent(xmlEvent);
        }
        //loop throug the rest of the document
        while (xmlEventIterator.hasNext()) {
            XMLEvent xmlEvent = xmlEventIterator.next();
            subOutputProcessorChain.reset();
            subOutputProcessorChain.processEvent(xmlEvent);
        }
        subOutputProcessorChain.reset();
        //call final on the rest of the chain
        subOutputProcessorChain.doFinal();
        //this processor is now finished and we can remove it now
        subOutputProcessorChain.removeProcessor(this);
    }

    @Override
    protected SignedInfoProcessor newSignedInfoProcessor(SignatureAlgorithm signatureAlgorithm) throws XMLSecurityException {
        this.signedInfoProcessor = new SignedInfoProcessor(getSecurityProperties(), getAction(), signatureAlgorithm);
        this.signedInfoProcessor.getAfterProcessors().add(SignatureEndingOutputProcessor.class.getName());
        return this.signedInfoProcessor;
    }

    @Override
    protected void processHeaderEvent(OutputProcessorChain outputProcessorChain) throws XMLStreamException, XMLSecurityException {
        super.processHeaderEvent(outputProcessorChain);

        SignatureValueSecurityEvent signatureValueSecurityEvent = new SignatureValueSecurityEvent(SecurityEvent.Event.SignatureValue);
        signatureValueSecurityEvent.setSignatureValue(this.signedInfoProcessor.getSignatureValue());
        ((WSSecurityContext) outputProcessorChain.getSecurityContext()).registerSecurityEvent(signatureValueSecurityEvent);
    }

    @Override
    protected void createKeyInfoStructureForSignature(
            OutputProcessorChain outputProcessorChain,
            SecurityToken securityToken,
            boolean useSingleCertificate)
            throws XMLStreamException, XMLSecurityException {

        WSSConstants.KeyIdentifierType keyIdentifierType = ((WSSSecurityProperties) getSecurityProperties()).getSignatureKeyIdentifierType();

        Map<QName, String> attributes = new HashMap<QName, String>();
        attributes.put(WSSConstants.ATT_wsu_Id, "STRId-" + UUID.randomUUID().toString());
        if ((keyIdentifierType == WSSConstants.KeyIdentifierType.BST_DIRECT_REFERENCE
                || keyIdentifierType == WSSConstants.KeyIdentifierType.BST_EMBEDDED)
                && !useSingleCertificate) {
            attributes.put(WSSConstants.ATT_wsse11_TokenType, WSSConstants.NS_X509PKIPathv1);
        } else if (WSSConstants.Saml10Token.equals(securityToken.getTokenType())
                || WSSConstants.Saml11Token.equals(securityToken.getTokenType())) {
            attributes.put(WSSConstants.ATT_wsse11_TokenType, WSSConstants.NS_SAML11_TOKEN_PROFILE_TYPE);
        } else if (WSSConstants.Saml20Token.equals(securityToken.getTokenType())) {
            attributes.put(WSSConstants.ATT_wsse11_TokenType, WSSConstants.NS_SAML20_TOKEN_PROFILE_TYPE);
        }
        createStartElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_wsse_SecurityTokenReference, attributes);

        X509Certificate[] x509Certificates = securityToken.getX509Certificates();
        String tokenId = securityToken.getId();

        if (keyIdentifierType == WSSConstants.KeyIdentifierType.ISSUER_SERIAL) {
            createX509IssuerSerialStructure(outputProcessorChain, x509Certificates);
        } else if (keyIdentifierType == WSSConstants.KeyIdentifierType.SKI_KEY_IDENTIFIER) {
            createX509SubjectKeyIdentifierStructure(outputProcessorChain, x509Certificates);
        } else if (keyIdentifierType == WSSConstants.KeyIdentifierType.X509_KEY_IDENTIFIER) {
            createX509KeyIdentifierStructure(outputProcessorChain, x509Certificates);
        } else if (keyIdentifierType == WSSConstants.KeyIdentifierType.THUMBPRINT_IDENTIFIER) {
            createThumbprintKeyIdentifierStructure(outputProcessorChain, x509Certificates);
        } else if (keyIdentifierType == WSSConstants.KeyIdentifierType.BST_EMBEDDED) {
            createBSTReferenceStructure(outputProcessorChain, tokenId, x509Certificates, useSingleCertificate, true);
        } else if (keyIdentifierType == WSSConstants.KeyIdentifierType.BST_DIRECT_REFERENCE) {
            createBSTReferenceStructure(outputProcessorChain, tokenId, x509Certificates, useSingleCertificate, false);
        } else if (keyIdentifierType == WSSConstants.KeyIdentifierType.EMBEDDED_SECURITY_TOKEN_REF) {
            createEmbeddedSecurityTokenReferenceStructure(outputProcessorChain, tokenId);
        } else if (keyIdentifierType == WSSConstants.KeyIdentifierType.EMEDDED_KEYIDENTIFIER_REF) {
            createEmbeddedKeyIdentifierStructure(outputProcessorChain, securityToken.getTokenType(), tokenId);
        } else if (keyIdentifierType == WSSConstants.KeyIdentifierType.USERNAMETOKEN_REFERENCE) {
            createUsernameTokenReferenceStructure(outputProcessorChain, tokenId);
        } else {
            throw new XMLSecurityException(XMLSecurityException.ErrorCode.FAILED_SIGNATURE, "unsupportedSecurityToken", keyIdentifierType.name());
        }
        createEndElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_wsse_SecurityTokenReference);
    }

    //todo common method
    protected void createX509SubjectKeyIdentifierStructure(OutputProcessorChain outputProcessorChain, X509Certificate[] x509Certificates) throws XMLSecurityException, XMLStreamException {
        // As per the 1.1 specification, SKI can only be used for a V3 certificate
        if (x509Certificates[0].getVersion() != 3) {
            throw new XMLSecurityException(XMLSecurityException.ErrorCode.FAILED_SIGNATURE, "invalidCertForSKI");
        }

        Map<QName, String> attributes = new HashMap<QName, String>();
        attributes.put(WSSConstants.ATT_NULL_EncodingType, WSSConstants.SOAPMESSAGE_NS10_BASE64_ENCODING);
        attributes.put(WSSConstants.ATT_NULL_ValueType, WSSConstants.NS_X509SubjectKeyIdentifier);
        createStartElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_wsse_KeyIdentifier, attributes);
        byte data[] = getSecurityProperties().getSignatureCrypto().getSKIBytesFromCert(x509Certificates[0]);
        createCharactersAndOutputAsEvent(outputProcessorChain, new Base64(76, new byte[]{'\n'}).encodeToString(data));
        createEndElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_wsse_KeyIdentifier);
    }

    //todo common method
    protected void createX509KeyIdentifierStructure(OutputProcessorChain outputProcessorChain, X509Certificate[] x509Certificates) throws XMLStreamException, XMLSecurityException {
        Map<QName, String> attributes = new HashMap<QName, String>();
        attributes.put(WSSConstants.ATT_NULL_EncodingType, WSSConstants.SOAPMESSAGE_NS10_BASE64_ENCODING);
        attributes.put(WSSConstants.ATT_NULL_ValueType, WSSConstants.NS_X509_V3_TYPE);
        createStartElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_wsse_KeyIdentifier, attributes);
        try {
            createCharactersAndOutputAsEvent(outputProcessorChain, new Base64(76, new byte[]{'\n'}).encodeToString(x509Certificates[0].getEncoded()));
        } catch (CertificateEncodingException e) {
            throw new XMLSecurityException(XMLSecurityException.ErrorCode.FAILED_SIGNATURE, e);
        }
        createEndElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_wsse_KeyIdentifier);
    }

    //todo common methdod
    protected void createThumbprintKeyIdentifierStructure(OutputProcessorChain outputProcessorChain, X509Certificate[] x509Certificates) throws XMLStreamException, XMLSecurityException {
        Map<QName, String> attributes = new HashMap<QName, String>();
        attributes.put(WSSConstants.ATT_NULL_EncodingType, WSSConstants.SOAPMESSAGE_NS10_BASE64_ENCODING);
        attributes.put(WSSConstants.ATT_NULL_ValueType, WSSConstants.NS_THUMBPRINT);
        createStartElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_wsse_KeyIdentifier, attributes);
        try {
            MessageDigest sha;
            sha = MessageDigest.getInstance("SHA-1");
            sha.reset();
            sha.update(x509Certificates[0].getEncoded());
            byte[] data = sha.digest();

            createCharactersAndOutputAsEvent(outputProcessorChain, new Base64(76, new byte[]{'\n'}).encodeToString(data));
        } catch (CertificateEncodingException e) {
            throw new XMLSecurityException(XMLSecurityException.ErrorCode.FAILED_SIGNATURE, e);
        } catch (NoSuchAlgorithmException e) {
            throw new XMLSecurityException(XMLSecurityException.ErrorCode.FAILED_SIGNATURE, e);
        }
        createEndElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_wsse_KeyIdentifier);
    }

    //todo common method
    protected void createBSTReferenceStructure(OutputProcessorChain outputProcessorChain, String referenceId, X509Certificate[] x509Certificates, boolean useSingleCertificate, boolean embed) throws XMLStreamException, XMLSecurityException {
        Map<QName, String> attributes = new HashMap<QName, String>();
        String valueType;
        if (useSingleCertificate) {
            valueType = WSSConstants.NS_X509_V3_TYPE;
        } else {
            valueType = WSSConstants.NS_X509PKIPathv1;
        }
        attributes.put(WSSConstants.ATT_NULL_URI, "#" + referenceId);
        attributes.put(WSSConstants.ATT_NULL_ValueType, valueType);
        createStartElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_wsse_Reference, attributes);
        if (embed) {
            createBinarySecurityTokenStructure(outputProcessorChain, referenceId, x509Certificates, useSingleCertificate);
        }
        createEndElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_wsse_Reference);
    }

    //todo common method
    protected void createBinarySecurityTokenStructure(OutputProcessorChain outputProcessorChain, String referenceId, X509Certificate[] x509Certificates, boolean useSingleCertificate) throws XMLStreamException, XMLSecurityException {
        Map<QName, String> attributes = new HashMap<QName, String>();
        String valueType;
        if (useSingleCertificate) {
            valueType = WSSConstants.NS_X509_V3_TYPE;
        } else {
            valueType = WSSConstants.NS_X509PKIPathv1;
        }
        attributes.put(WSSConstants.ATT_NULL_EncodingType, WSSConstants.SOAPMESSAGE_NS10_BASE64_ENCODING);
        attributes.put(WSSConstants.ATT_NULL_ValueType, valueType);
        attributes.put(WSSConstants.ATT_wsu_Id, referenceId);
        createStartElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_wsse_BinarySecurityToken, attributes);
        try {
            if (useSingleCertificate) {
                createCharactersAndOutputAsEvent(outputProcessorChain, new Base64(76, new byte[]{'\n'}).encodeToString(x509Certificates[0].getEncoded()));
            } else {
                try {
                    CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509", "BC");
                    List<X509Certificate> certificates = Arrays.asList(x509Certificates);
                    createCharactersAndOutputAsEvent(outputProcessorChain, new Base64(76, new byte[]{'\n'}).encodeToString(certificateFactory.generateCertPath(certificates).getEncoded()));
                } catch (CertificateException e) {
                    throw new XMLSecurityException(XMLSecurityException.ErrorCode.INVALID_SECURITY_TOKEN, e);
                } catch (NoSuchProviderException e) {
                    throw new XMLSecurityException(XMLSecurityException.ErrorCode.INVALID_SECURITY_TOKEN, e);
                }
            }
        } catch (CertificateEncodingException e) {
            throw new XMLSecurityException(XMLSecurityException.ErrorCode.FAILED_SIGNATURE, e);
        }
        createEndElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_wsse_BinarySecurityToken);
    }

    //todo common method
    protected void createEmbeddedKeyIdentifierStructure(OutputProcessorChain outputProcessorChain, XMLSecurityConstants.TokenType tokenType, String referenceId) throws XMLStreamException, XMLSecurityException {
        Map<QName, String> attributes = new HashMap<QName, String>();
        if (tokenType.equals(WSSConstants.Saml10Token) || tokenType.equals(WSSConstants.Saml11Token)) {
            attributes.put(WSSConstants.ATT_NULL_ValueType, WSSConstants.NS_SAML10_TYPE);
        } else if (tokenType.equals(WSSConstants.Saml20Token)) {
            attributes.put(WSSConstants.ATT_NULL_ValueType, WSSConstants.NS_SAML20_TYPE);
        }
        createStartElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_wsse_KeyIdentifier, attributes);
        createCharactersAndOutputAsEvent(outputProcessorChain, referenceId);
        createEndElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_wsse_KeyIdentifier);
    }

    //todo common method
    protected void createEmbeddedSecurityTokenReferenceStructure(OutputProcessorChain outputProcessorChain, String referenceId) throws XMLStreamException, XMLSecurityException {
        Map<QName, String> attributes = new HashMap<QName, String>();
        attributes.put(WSSConstants.ATT_NULL_URI, "#" + referenceId);
        createStartElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_wsse_Reference, attributes);
        createEndElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_wsse_Reference);
    }

    //todo common method:
    protected void createUsernameTokenReferenceStructure(OutputProcessorChain outputProcessorChain, String tokenId) throws XMLStreamException, XMLSecurityException {
        Map<QName, String> attributes = new HashMap<QName, String>();
        attributes.put(WSSConstants.ATT_NULL_URI, "#" + tokenId);
        attributes.put(WSSConstants.ATT_NULL_ValueType, WSSConstants.NS_USERNAMETOKEN_PROFILE_UsernameToken);
        createStartElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_wsse_Reference, attributes);
        createEndElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_wsse_Reference);
    }

    protected void createTransformsStructureForSignature(OutputProcessorChain subOutputProcessorChain, SignaturePartDef signaturePartDef) throws XMLStreamException, XMLSecurityException {
        Map<QName, String> attributes;
        if (signaturePartDef.getTransformAlgo() != null) {
            attributes = new HashMap<QName, String>();
            attributes.put(WSSConstants.ATT_NULL_Algorithm, signaturePartDef.getTransformAlgo());
            createStartElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_dsig_Transform, attributes);
            createStartElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_wsse_TransformationParameters, null);
            attributes = new HashMap<QName, String>();
            attributes.put(WSSConstants.ATT_NULL_Algorithm, signaturePartDef.getC14nAlgo());
            createStartElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_dsig_CanonicalizationMethod, attributes);
            createEndElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_dsig_CanonicalizationMethod);
            createEndElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_wsse_TransformationParameters);
            createEndElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_dsig_Transform);
        } else {
            attributes = new HashMap<QName, String>();
            attributes.put(WSSConstants.ATT_NULL_Algorithm, signaturePartDef.getC14nAlgo());
            createStartElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_dsig_Transform, attributes);
            createEndElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_dsig_Transform);
        }
    }
}
