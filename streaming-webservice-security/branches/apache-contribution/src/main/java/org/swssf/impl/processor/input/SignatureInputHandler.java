/**
 * Copyright 2010, 2011 Marc Giger
 *
 * This file is part of the streaming-webservice-security-framework (swssf).
 *
 * The streaming-webservice-security-framework is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * The streaming-webservice-security-framework is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with the streaming-webservice-security-framework.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.swssf.impl.processor.input;

import org.swssf.ext.*;
import org.swssf.impl.algorithms.SignatureAlgorithm;
import org.swssf.impl.algorithms.SignatureAlgorithmFactory;
import org.swssf.impl.securityToken.SecurityTokenFactory;
import org.swssf.impl.util.SignerOutputStream;
import org.swssf.securityEvent.AlgorithmSuiteSecurityEvent;
import org.swssf.securityEvent.SecurityEvent;
import org.swssf.securityEvent.SignatureTokenSecurityEvent;
import org.w3._2000._09.xmldsig_.KeyInfoType;
import org.w3._2000._09.xmldsig_.SignatureType;

import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.InvocationTargetException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.util.Deque;
import java.util.Iterator;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class SignatureInputHandler extends AbstractInputSecurityHeaderHandler {

    public SignatureInputHandler(InputProcessorChain inputProcessorChain, SecurityProperties securityProperties, Deque<XMLEvent> eventQueue, Integer index) throws WSSecurityException, XMLStreamException {

        final SignatureType signatureType = (SignatureType) parseStructure(eventQueue, index);
        verifySignedInfo(inputProcessorChain, securityProperties, signatureType, eventQueue, index);
    }

    @Override
    protected Parseable getParseable(StartElement startElement) {
        return new SignatureType(startElement);
    }

    private void verifySignedInfo(InputProcessorChain inputProcessorChain, SecurityProperties securityProperties, SignatureType signatureType, Deque<XMLEvent> eventDeque, int index) throws WSSecurityException, XMLStreamException {
        //todo reparse SignedInfo when custom canonicalization method is used
        //verify SignedInfo
        SignatureVerifier signatureVerifier = new SignatureVerifier(signatureType, inputProcessorChain.getSecurityContext(), securityProperties);

        Iterator<XMLEvent> iterator = eventDeque.descendingIterator();
        //skip to <Signature> Element
        int i = 0;
        while (i < index) {
            iterator.next();
            i++;
        }

        boolean verifyElement = false;
        while (iterator.hasNext()) {
            XMLEvent xmlEvent = iterator.next();
            if (xmlEvent.isStartElement() && xmlEvent.asStartElement().getName().equals(Constants.TAG_dsig_SignedInfo)) {
                verifyElement = true;
            } else if (xmlEvent.isEndElement() && xmlEvent.asEndElement().getName().equals(Constants.TAG_dsig_SignedInfo)) {
                signatureVerifier.processEvent(xmlEvent);
                break;
            }
            if (verifyElement) {
                signatureVerifier.processEvent(xmlEvent);
            }
        }
        signatureVerifier.doFinal();

        //add processors to verify references
        inputProcessorChain.addProcessor(new SignatureReferenceVerifyInputProcessor(signatureType, securityProperties));
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

    public static class SignatureVerifier {

        private SignatureType signatureType;
        private SecurityContext securityContext;
        private SecurityProperties securityProperties;

        private SignerOutputStream signerOutputStream;
        private OutputStream bufferedSignerOutputStream;
        private Transformer transformer;

        public SignatureVerifier(SignatureType signatureType, SecurityContext securityContext, SecurityProperties securityProperties) throws WSSecurityException {
            this.signatureType = signatureType;
            this.securityContext = securityContext;
            this.securityProperties = securityProperties;

            try {
                createSignatureAlgorithm();
            } catch (Exception e) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_CHECK, e);
            }
        }

        private void createSignatureAlgorithm() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, CertificateException, WSSecurityException {
            KeyInfoType keyInfoType = signatureType.getKeyInfo();
            SecurityToken securityToken = SecurityTokenFactory.newInstance().getSecurityToken(keyInfoType, securityProperties.getSignatureVerificationCrypto(), securityProperties.getCallbackHandler(), securityContext, this);
            securityToken.verify();

            SignatureTokenSecurityEvent signatureTokenSecurityEvent = new SignatureTokenSecurityEvent(SecurityEvent.Event.SignatureToken);
            signatureTokenSecurityEvent.setSecurityToken(securityToken);
            signatureTokenSecurityEvent.setSignatureValue(signatureType.getSignatureValue().getValue());
            securityContext.registerSecurityEvent(signatureTokenSecurityEvent);

            /*AlgorithmSuiteSecurityEvent algorithmSuiteSecurityEvent = new AlgorithmSuiteSecurityEvent(SecurityEvent.Event.AlgorithmSuite);
            algorithmSuiteSecurityEvent.setAlgorithmURI(signatureType.getSignedInfo().getSignatureMethod().getAlgorithm());
            algorithmSuiteSecurityEvent.setKeyUsage();
            securityContext.registerSecurityEvent(algorithmSuiteSecurityEvent);
            */

            AlgorithmSuiteSecurityEvent algorithmSuiteSecurityEvent = new AlgorithmSuiteSecurityEvent(SecurityEvent.Event.AlgorithmSuite);
            algorithmSuiteSecurityEvent.setAlgorithmURI(signatureType.getSignedInfo().getCanonicalizationMethod().getAlgorithm());
            algorithmSuiteSecurityEvent.setKeyUsage(Constants.KeyUsage.C14n);
            securityContext.registerSecurityEvent(algorithmSuiteSecurityEvent);

            Key verifyKey;
            if (securityToken.isAsymmetric()) {
                verifyKey = securityToken.getPublicKey(Constants.KeyUsage.Asym_Sig);
            } else {
                verifyKey = securityToken.getSecretKey(
                        signatureType.getSignedInfo().getSignatureMethod().getAlgorithm(), Constants.KeyUsage.Sym_Sig);
            }

            SignatureAlgorithm signatureAlgorithm = SignatureAlgorithmFactory.getInstance().getSignatureAlgorithm(signatureType.getSignedInfo().getSignatureMethod().getAlgorithm());
            signatureAlgorithm.engineInitVerify(verifyKey);
            signerOutputStream = new SignerOutputStream(signatureAlgorithm);
            bufferedSignerOutputStream = new BufferedOutputStream(signerOutputStream);

            try {
                transformer = Utils.getTransformer(signatureType.getSignedInfo().getCanonicalizationMethod().getInclusiveNamespaces(), this.bufferedSignerOutputStream, signatureType.getSignedInfo().getCanonicalizationMethod().getAlgorithm());
            } catch (NoSuchMethodException e) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_CHECK, e);
            } catch (InstantiationException e) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_CHECK, e);
            } catch (IllegalAccessException e) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_CHECK, e);
            } catch (InvocationTargetException e) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_CHECK, e);
            }
        }

        public void processEvent(XMLEvent xmlEvent) throws XMLStreamException {
            transformer.transform(xmlEvent);
        }

        public void doFinal() throws WSSecurityException {
            try {
                bufferedSignerOutputStream.close();
                if (!signerOutputStream.verify(signatureType.getSignatureValue().getValue())) {
                    throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_CHECK);
                }
            } catch (IOException e) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_CHECK, e);
            }
        }
    }
}
