package ch.gigerstyle.xmlsec.processorImpl.input;

import ch.gigerstyle.xmlsec.*;
import org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_secext_1_0.SecurityTokenReferenceType;
import org.w3._2000._09.xmldsig_.*;

import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * User: giger
 * Date: May 14, 2010
 * Time: 1:32:13 PM
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
public class SignatureInputProcessor extends AbstractInputProcessor {

    private Map<String, SignatureType> signatureTypes = new HashMap<String, SignatureType>();
    private SignatureType currentSignatureType;
    private ReferenceType currentReferenceType;
    private TransformType currentTransformType;

    private boolean recordSignedInfo = false;
    private List<XMLEvent> signedInfoXMLEvents = new ArrayList<XMLEvent>();

    public SignatureInputProcessor(SecurityProperties securityProperties) {
        super(securityProperties);
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

    public void processEvent(XMLEvent xmlEvent, InputProcessorChain inputProcessorChain, SecurityContext securityContext) throws XMLStreamException, XMLSecurityException {

        if (xmlEvent.isStartElement()) {
            StartElement startElement = xmlEvent.asStartElement();

            if (startElement.getName().equals(Constants.TAG_dsig_Signature)) {
                currentSignatureType = new SignatureType();

                Attribute attribute = startElement.getAttributeByName(Constants.ATT_NULL_Id);
                if (attribute != null) {
                    currentSignatureType.setId(attribute.getValue());
                    signatureTypes.put(attribute.getValue(), currentSignatureType);
                } else {
                    signatureTypes.put(null, currentSignatureType);
                }
            } else if (currentSignatureType == null) {
                //do nothing...fall out
            } else if (startElement.getName().equals(Constants.TAG_dsig_SignedInfo)) {
                recordSignedInfo = true;
                SignedInfoType signedInfoType = new SignedInfoType();

                Attribute id = startElement.getAttributeByName(Constants.ATT_NULL_Id);
                if (id != null) {
                    signedInfoType.setId(id.getValue());
                }
                currentSignatureType.setSignedInfo(signedInfoType);
            } else if (startElement.getName().equals(Constants.TAG_dsig_CanonicalizationMethod)) {
                CanonicalizationMethodType canonicalizationMethodType = new CanonicalizationMethodType();
                //optional:
                Attribute algorithm = startElement.getAttributeByName(Constants.ATT_NULL_Algorithm);
                if (algorithm != null) {
                    canonicalizationMethodType.setAlgorithm(algorithm.getValue());
                }
                currentSignatureType.getSignedInfo().setCanonicalizationMethod(canonicalizationMethodType);
            } else if (startElement.getName().equals(Constants.TAG_dsig_SignatureMethod)) {
                SignatureMethodType signatureMethodType = new SignatureMethodType();
                //optional:
                Attribute algorithm = startElement.getAttributeByName(Constants.ATT_NULL_Algorithm);
                if (algorithm != null) {
                    signatureMethodType.setAlgorithm(algorithm.getValue());
                }
                currentSignatureType.getSignedInfo().setSignatureMethod(signatureMethodType);
            } else if (startElement.getName().equals(Constants.TAG_dsig_Reference)) {
                ReferenceType referenceType = new ReferenceType();

                Attribute id = startElement.getAttributeByName(Constants.ATT_NULL_Id);
                if (id != null) {
                    referenceType.setId(id.getValue());
                }

                Attribute uri = startElement.getAttributeByName(Constants.ATT_NULL_URI);
                if (uri != null) {
                    referenceType.setURI(Utils.dropReferenceMarker(uri.getValue()));
                }

                Attribute type = startElement.getAttributeByName(Constants.ATT_NULL_Type);
                if (type != null) {
                    referenceType.setType(type.getValue());
                }
                //todo easier api for lists with unknown types @see cxf
                currentSignatureType.getSignedInfo().getReference().add(referenceType);
                currentReferenceType = referenceType;
            } else if (startElement.getName().equals(Constants.TAG_dsig_Transforms)) {
                TransformsType transformsType = new TransformsType();
                currentReferenceType.setTransforms(transformsType);
            } else if (startElement.getName().equals(Constants.TAG_dsig_Transform)) {
                Attribute algorithm = startElement.getAttributeByName(Constants.ATT_NULL_Algorithm);
                if (algorithm == null) {
                    throw new XMLSecurityException("Missing Attribute " + Constants.ATT_NULL_Algorithm);
                }

                TransformType transformType = new TransformType();
                transformType.setAlgorithm(algorithm.getValue());
                currentReferenceType.getTransforms().getTransform().add(transformType);
                currentTransformType = transformType;
            } else if (startElement.getName().equals(Constants.TAG_dsig_DigestMethod)) {
                Attribute algorithm = startElement.getAttributeByName(Constants.ATT_NULL_Algorithm);
                if (algorithm == null) {
                    throw new XMLSecurityException("Missing Attribute " + Constants.ATT_NULL_Algorithm);
                }
                DigestMethodType digestMethodType = new DigestMethodType();
                digestMethodType.setAlgorithm(algorithm.getValue());
                currentReferenceType.setDigestMethod(digestMethodType);
            } else if (startElement.getName().equals(Constants.TAG_dsig_DigestValue)) {
                //nothing todo
            } else if (startElement.getName().equals(Constants.TAG_dsig_SignatureValue)) {
                SignatureValueType signatureValueType = new SignatureValueType();

                Attribute id = startElement.getAttributeByName(Constants.ATT_NULL_Id);
                if (id != null) {
                    signatureValueType.setId(id.getValue());
                }
                currentSignatureType.setSignatureValue(signatureValueType);
            } else if (startElement.getName().equals(Constants.TAG_dsig_KeyInfo)) {
                KeyInfoType keyInfoType = new KeyInfoType();

                Attribute id = startElement.getAttributeByName(Constants.ATT_NULL_Id);
                if (id != null) {
                    keyInfoType.setId(id.getValue());
                }
                currentSignatureType.setKeyInfo(keyInfoType);
            } else if (startElement.getName().equals(Constants.TAG_wsse_SecurityTokenReference)) {
                SecurityTokenReferenceType securityTokenReferenceType = new SecurityTokenReferenceType();
                //optional:
                Attribute idAttribute = startElement.getAttributeByName(Constants.ATT_wsu_Id);
                if (idAttribute != null) {
                    securityTokenReferenceType.setId(idAttribute.getValue());
                }
                currentSignatureType.getKeyInfo().getContent().add(securityTokenReferenceType);
            } else if (startElement.getName().equals(Constants.TAG_wsse_Reference)) {
                org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_secext_1_0.ReferenceType referenceType
                        = new org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_secext_1_0.ReferenceType();

                Attribute uri = startElement.getAttributeByName(Constants.ATT_NULL_URI);
                if (uri != null) {
                    referenceType.setURI(uri.getValue());
                }
                Attribute valueType = startElement.getAttributeByName(Constants.ATT_NULL_ValueType);
                if (valueType != null) {
                    referenceType.setValueType(valueType.getValue());
                }
                //todo easier api for lists with unknown types @see cxf
                ((SecurityTokenReferenceType) currentSignatureType.getKeyInfo().getContent().get(0)).getAny().add(referenceType);
            }
        } else if (currentSignatureType != null && xmlEvent.isCharacters()) {
            //todo handle multiple character events for same text-node
            Characters characters = xmlEvent.asCharacters();
            if (!characters.isWhiteSpace() && getLastStartElementName().equals(Constants.TAG_dsig_DigestValue)) {
                currentReferenceType.setDigestValue(characters.getData().getBytes());
            } else if (!characters.isWhiteSpace() && getLastStartElementName().equals(Constants.TAG_dsig_SignatureValue)) {
                currentSignatureType.getSignatureValue().setValue(characters.getData().getBytes());
            }
        } else if (currentSignatureType != null && xmlEvent.isEndElement()) {
            EndElement endElement = xmlEvent.asEndElement();

            if (endElement.getName().equals(Constants.TAG_dsig_SignedInfo)) {
                signedInfoXMLEvents.add(xmlEvent);
                recordSignedInfo = false;
                currentReferenceType = null;
                currentTransformType = null;
            } else if (endElement.getName().equals(Constants.TAG_dsig_Signature)) {
                //todo reparse SignedInfo when custom canonicalization method is used
                //verify SignedInfo
                SignatureVerifier signatureVerifier = new SignatureVerifier(currentSignatureType, securityContext);
                for (int i = 0; i < signedInfoXMLEvents.size(); i++) {
                    XMLEvent signedInfoEvent = signedInfoXMLEvents.get(i);
                    signatureVerifier.processEvent(signedInfoEvent);
                }
                signatureVerifier.doFinal();

                //add processors to verify references
                inputProcessorChain.addProcessor(new SignatureReferenceVerifyInputProcessor(currentSignatureType, getSecurityProperties()));
                currentSignatureType = null;
            }
            //probably we can remove this processor from the chain now?
        }

        if (recordSignedInfo) {
            signedInfoXMLEvents.add(xmlEvent);
        }

        inputProcessorChain.processEvent(xmlEvent);
    }
}
