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

import org.swssf.crypto.Crypto;
import org.swssf.ext.*;
import org.swssf.impl.securityToken.ProcessorInfoSecurityToken;
import org.swssf.impl.securityToken.X509SecurityToken;
import org.swssf.securityEvent.InitiatorSignatureTokenSecurityEvent;
import org.swssf.securityEvent.SecurityEvent;

import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;
import java.security.Key;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.UUID;

/**
 * @author $Author: giger $
 * @version $Revision: 272 $ $Date: 2010-12-23 14:30:56 +0100 (Thu, 23 Dec 2010) $
 */
public class BinarySecurityTokenOutputProcessor extends AbstractOutputProcessor {

    public BinarySecurityTokenOutputProcessor(SecurityProperties securityProperties, Constants.Action action) throws WSSecurityException {
        super(securityProperties, action);
    }

    @Override
    public void processEvent(XMLEvent xmlEvent, OutputProcessorChain outputProcessorChain) throws XMLStreamException, WSSecurityException {
        try {
            final String bstId = "BST-" + UUID.randomUUID().toString();
            final X509Certificate[] x509Certificates;
            final Key key;

            switch (action) {
                case SIGNATURE:
                case SAML_TOKEN_SIGNED:
                case SIGNATURE_WITH_DERIVED_KEY:
                    String alias = getSecurityProperties().getSignatureUser();
                    WSPasswordCallback pwCb = new WSPasswordCallback(alias, WSPasswordCallback.Usage.SIGNATURE);
                    Utils.doPasswordCallback(getSecurityProperties().getCallbackHandler(), pwCb);
                    String password = pwCb.getPassword();
                    if (password == null) {
                        throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_SIGNATURE, "noPassword", alias);
                    }
                    key = getSecurityProperties().getSignatureCrypto().getPrivateKey(alias, password);
                    x509Certificates = getSecurityProperties().getSignatureCrypto().getCertificates(getSecurityProperties().getSignatureUser());
                    if (x509Certificates == null || x509Certificates.length == 0) {
                        throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_SIGNATURE, "noUserCertsFound", alias);
                    }
                    break;
                case ENCRYPT:
                case ENCRYPT_WITH_DERIVED_KEY:
                    X509Certificate x509Certificate = getReqSigCert(outputProcessorChain.getSecurityContext());
                    if (x509Certificate != null && getSecurityProperties().isUseReqSigCertForEncryption()) {
                        x509Certificates = new X509Certificate[1];
                        x509Certificates[0] = x509Certificate;
                    } else if (getSecurityProperties().getEncryptionUseThisCertificate() != null) {
                        x509Certificate = getSecurityProperties().getEncryptionUseThisCertificate();
                        x509Certificates = new X509Certificate[1];
                        x509Certificates[0] = x509Certificate;
                    } else {
                        x509Certificates = getSecurityProperties().getEncryptionCrypto().getCertificates(getSecurityProperties().getEncryptionUser());
                        if (x509Certificates == null || x509Certificates.length == 0) {
                            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_ENCRYPTION, "noUserCertsFound", getSecurityProperties().getEncryptionUser());
                        }
                    }
                    key = null;
                    break;
                default:
                    x509Certificates = null;
                    key = null;
                    break;
            }

            final ProcessorInfoSecurityToken binarySecurityToken = new ProcessorInfoSecurityToken() {

                private OutputProcessor outputProcessor;

                public String getId() {
                    return bstId;
                }

                public void setProcessor(OutputProcessor outputProcessor) {
                    this.outputProcessor = outputProcessor;
                }

                public Object getProccesor() {
                    return outputProcessor;
                }

                public boolean isAsymmetric() {
                    return true;
                }

                public Key getSecretKey(String algorithmURI) throws WSSecurityException {
                    return key;
                }

                public PublicKey getPublicKey() throws WSSecurityException {
                    return x509Certificates[0].getPublicKey();
                }

                public X509Certificate[] getX509Certificates() throws WSSecurityException {
                    return x509Certificates;
                }

                public void verify() throws WSSecurityException {
                }

                public SecurityToken getKeyWrappingToken() {
                    return null;
                }

                public String getKeyWrappingTokenAlgorithm() {
                    return null;
                }

                public Constants.KeyIdentifierType getKeyIdentifierType() {
                    return null;
                }
            };

            final SecurityTokenProvider binarySecurityTokenProvider = new SecurityTokenProvider() {
                public SecurityToken getSecurityToken(Crypto crypto) throws WSSecurityException {
                    return binarySecurityToken;
                }

                public String getId() {
                    return bstId;
                }
            };

            switch (action) {
                case SIGNATURE:
                case SAML_TOKEN_SIGNED:
                    outputProcessorChain.getSecurityContext().put(Constants.PROP_USE_THIS_TOKEN_ID_FOR_SIGNATURE, bstId);
                    if (getSecurityProperties().getSignatureKeyIdentifierType() == Constants.KeyIdentifierType.BST_DIRECT_REFERENCE) {
                        outputProcessorChain.getSecurityContext().put(Constants.PROP_APPEND_SIGNATURE_ON_THIS_ID, bstId);
                        FinalBinarySecurityTokenOutputProcessor finalBinarySecurityTokenOutputProcessor = new FinalBinarySecurityTokenOutputProcessor(getSecurityProperties(), getAction(), binarySecurityToken);
                        finalBinarySecurityTokenOutputProcessor.getBeforeProcessors().add(SignatureOutputProcessor.class.getName());
                        outputProcessorChain.addProcessor(finalBinarySecurityTokenOutputProcessor);
                        binarySecurityToken.setProcessor(finalBinarySecurityTokenOutputProcessor);
                    }
                    break;
                case ENCRYPT:
                    outputProcessorChain.getSecurityContext().put(Constants.PROP_USE_THIS_TOKEN_ID_FOR_ENCRYPTED_KEY, bstId);
                    if (getSecurityProperties().getEncryptionKeyIdentifierType() == Constants.KeyIdentifierType.BST_DIRECT_REFERENCE) {
                        FinalBinarySecurityTokenOutputProcessor finalBinarySecurityTokenOutputProcessor = new FinalBinarySecurityTokenOutputProcessor(getSecurityProperties(), getAction(), binarySecurityToken);
                        finalBinarySecurityTokenOutputProcessor.getAfterProcessors().add(EncryptEndingOutputProcessor.class.getName());
                        outputProcessorChain.addProcessor(finalBinarySecurityTokenOutputProcessor);
                        binarySecurityToken.setProcessor(finalBinarySecurityTokenOutputProcessor);
                    }
                    break;
                case SIGNATURE_WITH_DERIVED_KEY:
                case ENCRYPT_WITH_DERIVED_KEY:
                    switch (getSecurityProperties().getDerivedKeyTokenReference()) {

                        case DirectReference:
                            outputProcessorChain.getSecurityContext().put(Constants.PROP_USE_THIS_TOKEN_ID_FOR_DERIVED_KEY, bstId);
                            break;
                        case EncryptedKey:
                            outputProcessorChain.getSecurityContext().put(Constants.PROP_USE_THIS_TOKEN_ID_FOR_ENCRYPTED_KEY, bstId);
                            break;
                        case SecurityContextToken:
                            outputProcessorChain.getSecurityContext().put(Constants.PROP_USE_THIS_TOKEN_ID_FOR_SECURITYCONTEXTTOKEN, bstId);
                            break;
                    }
                    if ((getAction() == Constants.Action.ENCRYPT_WITH_DERIVED_KEY
                            && getSecurityProperties().getEncryptionKeyIdentifierType() == Constants.KeyIdentifierType.BST_DIRECT_REFERENCE)
                            || (getAction() == Constants.Action.SIGNATURE_WITH_DERIVED_KEY
                            && getSecurityProperties().getSignatureKeyIdentifierType() == Constants.KeyIdentifierType.BST_DIRECT_REFERENCE)) {
                        FinalBinarySecurityTokenOutputProcessor finalBinarySecurityTokenOutputProcessor = new FinalBinarySecurityTokenOutputProcessor(getSecurityProperties(), getAction(), binarySecurityToken);
                        finalBinarySecurityTokenOutputProcessor.getAfterProcessors().add(EncryptEndingOutputProcessor.class.getName());
                        outputProcessorChain.addProcessor(finalBinarySecurityTokenOutputProcessor);
                        binarySecurityToken.setProcessor(finalBinarySecurityTokenOutputProcessor);
                    }
                    break;
            }

            outputProcessorChain.getSecurityContext().registerSecurityTokenProvider(bstId, binarySecurityTokenProvider);

        } finally {
            outputProcessorChain.removeProcessor(this);
        }
        outputProcessorChain.processEvent(xmlEvent);
    }

    private X509Certificate getReqSigCert(SecurityContext securityContext) throws WSSecurityException {
        List<SecurityEvent> securityEventList = securityContext.getAsList(SecurityEvent.class);
        if (securityEventList != null) {
            for (int i = 0; i < securityEventList.size(); i++) {
                SecurityEvent securityEvent = securityEventList.get(i);
                if (securityEvent.getSecurityEventType() == SecurityEvent.Event.InitiatorSignatureToken) {
                    InitiatorSignatureTokenSecurityEvent initiatorSignatureTokenSecurityEvent = (InitiatorSignatureTokenSecurityEvent) securityEvent;
                    SecurityToken securityToken = initiatorSignatureTokenSecurityEvent.getSecurityToken();
                    if (securityToken instanceof X509SecurityToken) {
                        X509SecurityToken x509SecurityToken = (X509SecurityToken) securityToken;
                        return x509SecurityToken.getX509Certificates()[0];
                    }
                }
            }
        }
        return null;
    }

    class FinalBinarySecurityTokenOutputProcessor extends AbstractOutputProcessor {

        private SecurityToken securityToken;

        FinalBinarySecurityTokenOutputProcessor(SecurityProperties securityProperties, Constants.Action action, SecurityToken securityToken) throws WSSecurityException {
            super(securityProperties, action);
            this.getAfterProcessors().add(BinarySecurityTokenOutputProcessor.class.getName());
            this.securityToken = securityToken;
        }

        @Override
        public void processEvent(XMLEvent xmlEvent, OutputProcessorChain outputProcessorChain) throws XMLStreamException, WSSecurityException {
            outputProcessorChain.processEvent(xmlEvent);
            if (xmlEvent.isStartElement()) {
                StartElement startElement = xmlEvent.asStartElement();
                if (outputProcessorChain.getDocumentContext().isInSecurityHeader() && startElement.getName().equals(Constants.TAG_wsse_Security)) {
                    OutputProcessorChain subOutputProcessorChain = outputProcessorChain.createSubChain(this);

                    boolean useSingleCertificate = getSecurityProperties().isUseSingleCert();
                    createBinarySecurityTokenStructure(subOutputProcessorChain, securityToken.getId(), securityToken.getX509Certificates(), useSingleCertificate);

                    outputProcessorChain.removeProcessor(this);
                }
            }
        }
    }
}
