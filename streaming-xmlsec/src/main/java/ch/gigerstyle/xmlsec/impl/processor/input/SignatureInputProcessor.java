package ch.gigerstyle.xmlsec.impl.processor.input;

import ch.gigerstyle.xmlsec.config.JCEAlgorithmMapper;
import ch.gigerstyle.xmlsec.ext.*;
import ch.gigerstyle.xmlsec.impl.SecurityTokenFactory;
import ch.gigerstyle.xmlsec.impl.transformer.canonicalizer.Canonicalizer20010315ExclOmitCommentsTransformer;
import ch.gigerstyle.xmlsec.impl.transformer.canonicalizer.Canonicalizer20010315Transformer;
import ch.gigerstyle.xmlsec.impl.util.SignerOutputStream;
import org.bouncycastle.util.encoders.Base64;
import org.w3._2000._09.xmldsig_.KeyInfoType;
import org.w3._2000._09.xmldsig_.SignatureType;

import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.EndElement;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.List;

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

    private SignatureType currentSignatureType;
    private boolean isFinishedcurrentSignatureType;

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

    @Override
    public void processSecurityHeaderEvent(XMLEvent xmlEvent, InputProcessorChain inputProcessorChain, SecurityContext securityContext) throws XMLStreamException, XMLSecurityException {

        if (currentSignatureType != null) {
            try {
                isFinishedcurrentSignatureType = currentSignatureType.parseXMLEvent(xmlEvent);
                if (isFinishedcurrentSignatureType) {
                    currentSignatureType.validate();
                }
            } catch (ParseException e) {
                throw new XMLSecurityException(e);
            }
        }

        if (xmlEvent.isStartElement()) {
            StartElement startElement = xmlEvent.asStartElement();

            if (startElement.getName().equals(Constants.TAG_dsig_Signature)) {
                currentSignatureType = new SignatureType(startElement);
            } else if (currentSignatureType != null && startElement.getName().equals(Constants.TAG_dsig_SignedInfo)) {
                recordSignedInfo = true;
            }
        } else if (currentSignatureType != null && xmlEvent.isEndElement()) {
            EndElement endElement = xmlEvent.asEndElement();

            if (endElement.getName().equals(Constants.TAG_dsig_SignedInfo)) {
                signedInfoXMLEvents.add(xmlEvent);
                recordSignedInfo = false;
            }
        }

        if (recordSignedInfo) {
            signedInfoXMLEvents.add(xmlEvent);
        }

        if (currentSignatureType != null && isFinishedcurrentSignatureType) {
            try {
                //todo reparse SignedInfo when custom canonicalization method is used
                //verify SignedInfo
                SignatureVerifier signatureVerifier = new SignatureVerifier(currentSignatureType, securityContext, getSecurityProperties());
                for (int i = 0; i < signedInfoXMLEvents.size(); i++) {
                    XMLEvent signedInfoEvent = signedInfoXMLEvents.get(i);
                    signatureVerifier.processEvent(signedInfoEvent);
                }
                signatureVerifier.doFinal();

                //add processors to verify references
                inputProcessorChain.addProcessor(new SignatureReferenceVerifyInputProcessor(currentSignatureType, getSecurityProperties()));
                currentSignatureType = null;
            } finally {
                inputProcessorChain.removeProcessor(this);
                currentSignatureType = null;
                isFinishedcurrentSignatureType = false;
            }
        }

        inputProcessorChain.processSecurityHeaderEvent(xmlEvent);
    }

    public void processEvent(XMLEvent xmlEvent, InputProcessorChain inputProcessorChain, SecurityContext securityContext) throws XMLStreamException, XMLSecurityException {
        //this method should not be called (processor will be removed after processing header
        inputProcessorChain.processEvent(xmlEvent);
    }

    public static class SignatureVerifier {

        private SignatureType signatureType;
        private SecurityContext securityContext;
        private SecurityProperties securityProperties;

        private SignerOutputStream signerOutputStream;
        private OutputStream bufferedSignerOutputStream;
        private Canonicalizer20010315Transformer canonicalizer20010315Transformer = new Canonicalizer20010315ExclOmitCommentsTransformer(null);

        public SignatureVerifier(SignatureType signatureType, SecurityContext securityContext, SecurityProperties securityProperties) throws XMLSecurityException {
            this.signatureType = signatureType;
            this.securityContext = securityContext;
            this.securityProperties = securityProperties;

            try {
                createSignatureAlgorithm();
            } catch (Exception e) {
                throw new XMLSecurityException(e.getMessage(), e);
            }
        }

        private void createSignatureAlgorithm() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, CertificateException, XMLSecurityException {
            String signatureAlgorithm = JCEAlgorithmMapper.translateURItoJCEID(signatureType.getSignedInfo().getSignatureMethod().getAlgorithm());
            Signature signature = Signature.getInstance(signatureAlgorithm, "BC");

            KeyInfoType keyInfoType = signatureType.getKeyInfo();
            SecurityToken securityToken = SecurityTokenFactory.newInstance().getSecurityToken(keyInfoType, securityProperties.getSignatureVerificationCrypto(), securityProperties.getCallbackHandler(), securityContext);
            //todo test verify:
            securityToken.verify();
            signature.initVerify(securityToken.getPublicKey());
            signerOutputStream = new SignerOutputStream(signature);
            bufferedSignerOutputStream = new BufferedOutputStream(signerOutputStream);
        }

        public void processEvent(XMLEvent xmlEvent) throws XMLStreamException {
            canonicalizer20010315Transformer.transform(xmlEvent, bufferedSignerOutputStream);
        }

        public void doFinal() throws XMLSecurityException {
            try {
                bufferedSignerOutputStream.close();
                if (!signerOutputStream.verify(Base64.decode(signatureType.getSignatureValue().getValue()))) {
                    throw new XMLSecurityException("Signature verification failed");
                }
            } catch (SignatureException e) {
                throw new XMLSecurityException(e);
            } catch (IOException e) {
                throw new XMLSecurityException(e);
            }
        }
    }
}
