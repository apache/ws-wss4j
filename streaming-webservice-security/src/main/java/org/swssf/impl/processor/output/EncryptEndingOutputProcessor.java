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
import org.swssf.impl.EncryptionPartDef;
import org.swssf.impl.securityToken.X509SecurityToken;
import org.swssf.impl.util.RFC2253Parser;
import org.swssf.securityEvent.InitiatorSignatureTokenSecurityEvent;
import org.swssf.securityEvent.SecurityEvent;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.*;

/**
 * Processor buffers encrypted XMLEvents, builds the EncryptedKey Security-Header,
 * and forwards then the buffered events.
 *
 * @author $Author: giger $
 * @version $Revision: 281 $ $Date: 2011-01-04 21:15:27 +0100 (Tue, 04 Jan 2011) $
 */
public class EncryptEndingOutputProcessor extends AbstractBufferingOutputProcessor {

    private Key symmetricKey;
    private String symmetricKeyId;
    private List<EncryptionPartDef> encryptionPartDefList;

    public EncryptEndingOutputProcessor(SecurityProperties securityProperties, EncryptOutputProcessor encryptOutputProcessor) throws WSSecurityException {
        super(securityProperties);
        this.getAfterProcessors().add(EncryptOutputProcessor.class.getName());
        this.getAfterProcessors().add(UsernameTokenOutputProcessor.class.getName());
        this.symmetricKey = encryptOutputProcessor.getSymmetricKey();
        this.symmetricKeyId = encryptOutputProcessor.getSymmetricKeyId();
        this.encryptionPartDefList = encryptOutputProcessor.getEncryptionPartDefList();
    }

    protected void processHeaderEvent(OutputProcessorChain outputProcessorChain) throws XMLStreamException, WSSecurityException {

        OutputProcessorChain subOutputProcessorChain = outputProcessorChain.createSubChain(this);

        //fetch the Certificate with the public key for symmetric session key encryption:
        X509Certificate x509Certificate = getReqSigCert(outputProcessorChain.getSecurityContext());

        if (!getSecurityProperties().isUseReqSigCertForEncryption() || x509Certificate == null) {
            if (getSecurityProperties().getEncryptionUseThisCertificate() != null) {
                x509Certificate = getSecurityProperties().getEncryptionUseThisCertificate();
            } else {
                X509Certificate[] certs = getSecurityProperties().getEncryptionCrypto().getCertificates(getSecurityProperties().getEncryptionUser());
                if (certs == null || certs.length <= 0) {
                    throw new WSSecurityException("noUserCertsFound for encryption for user " + getSecurityProperties().getEncryptionUser());
                }
                x509Certificate = certs[0];
            }
        }

        //the following if-else section builds the key references
        String certUri = "CertId-" + UUID.randomUUID().toString();
        BinarySecurityTokenType referencedBinarySecurityTokenType = null;
        if (getSecurityProperties().getEncryptionKeyIdentifierType() == Constants.KeyIdentifierType.BST_DIRECT_REFERENCE) {
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
                createCharactersAndOutputAsEvent(subOutputProcessorChain, new Base64(76, new byte[]{'\n'}).encodeToString(x509Certificate.getEncoded()));
            } catch (CertificateEncodingException e) {
                throw new WSSecurityException(WSSecurityException.FAILED_ENCRYPTION, null, e);
            }
            createEndElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_wsse_BinarySecurityToken);
        }

        Map<QName, String> attributes = new HashMap<QName, String>();
        attributes.put(Constants.ATT_NULL_Id, symmetricKeyId);
        createStartElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_xenc_EncryptedKey, attributes);

        attributes = new HashMap<QName, String>();
        attributes.put(Constants.ATT_NULL_Algorithm, getSecurityProperties().getEncryptionKeyTransportAlgorithm());
        createStartElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_xenc_EncryptionMethod, attributes);
        createEndElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_xenc_EncryptionMethod);
        createStartElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_dsig_KeyInfo, null);
        createStartElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_wsse_SecurityTokenReference, null);

        if (getSecurityProperties().getEncryptionKeyIdentifierType() == Constants.KeyIdentifierType.ISSUER_SERIAL) {

            createStartElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_dsig_X509Data, null);
            createStartElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_dsig_X509IssuerSerial, null);
            createStartElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_dsig_X509IssuerName, null);
            createCharactersAndOutputAsEvent(subOutputProcessorChain, RFC2253Parser.normalize(x509Certificate.getIssuerDN().getName(), true));
            createEndElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_dsig_X509IssuerName);
            createStartElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_dsig_X509SerialNumber, null);
            createCharactersAndOutputAsEvent(subOutputProcessorChain, x509Certificate.getSerialNumber().toString());
            createEndElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_dsig_X509SerialNumber);
            createEndElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_dsig_X509IssuerSerial);
            createEndElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_dsig_X509Data);
        } else if (getSecurityProperties().getEncryptionKeyIdentifierType() == Constants.KeyIdentifierType.SKI_KEY_IDENTIFIER) {
            // As per the 1.1 specification, SKI can only be used for a V3 certificate
            if (x509Certificate.getVersion() != 3) {
                throw new WSSecurityException(WSSecurityException.FAILED_ENCRYPTION, "invalidCertForSKI");
            }

            attributes = new HashMap<QName, String>();
            attributes.put(Constants.ATT_NULL_EncodingType, Constants.SOAPMESSAGE_NS10_BASE64_ENCODING);
            attributes.put(Constants.ATT_NULL_ValueType, Constants.NS_X509SubjectKeyIdentifier);
            createStartElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_wsse_KeyIdentifier, attributes);
            byte data[] = getSecurityProperties().getEncryptionCrypto().getSKIBytesFromCert(x509Certificate);
            createCharactersAndOutputAsEvent(subOutputProcessorChain, new Base64(76, new byte[]{'\n'}).encodeToString(data));
            createEndElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_wsse_KeyIdentifier);
        } else if (getSecurityProperties().getEncryptionKeyIdentifierType() == Constants.KeyIdentifierType.X509_KEY_IDENTIFIER) {

            attributes = new HashMap<QName, String>();
            attributes.put(Constants.ATT_NULL_EncodingType, Constants.SOAPMESSAGE_NS10_BASE64_ENCODING);
            attributes.put(Constants.ATT_NULL_ValueType, Constants.NS_X509_V3_TYPE);
            createStartElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_wsse_KeyIdentifier, attributes);
            try {
                createCharactersAndOutputAsEvent(subOutputProcessorChain, new Base64(76, new byte[]{'\n'}).encodeToString(x509Certificate.getEncoded()));
            } catch (CertificateEncodingException e) {
                throw new WSSecurityException(WSSecurityException.FAILED_ENCRYPTION, null, e);
            }
            createEndElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_wsse_KeyIdentifier);
        } else if (getSecurityProperties().getEncryptionKeyIdentifierType() == Constants.KeyIdentifierType.THUMBPRINT_IDENTIFIER) {

            attributes = new HashMap<QName, String>();
            attributes.put(Constants.ATT_NULL_EncodingType, Constants.SOAPMESSAGE_NS10_BASE64_ENCODING);
            attributes.put(Constants.ATT_NULL_ValueType, Constants.NS_THUMBPRINT);
            createStartElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_wsse_KeyIdentifier, attributes);
            try {
                MessageDigest sha = null;
                sha = MessageDigest.getInstance("SHA-1");
                sha.reset();
                sha.update(x509Certificate.getEncoded());
                byte[] data = sha.digest();

                createCharactersAndOutputAsEvent(subOutputProcessorChain, new Base64(76, new byte[]{'\n'}).encodeToString(data));
            } catch (CertificateEncodingException e) {
                throw new WSSecurityException(WSSecurityException.FAILED_ENCRYPTION, null, e);
            } catch (NoSuchAlgorithmException e) {
                throw new WSSecurityException(WSSecurityException.FAILED_ENCRYPTION, null, e);
            }
            createEndElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_wsse_KeyIdentifier);
        } else if (getSecurityProperties().getEncryptionKeyIdentifierType() == Constants.KeyIdentifierType.BST_EMBEDDED) {
            attributes = new HashMap<QName, String>();
            attributes.put(Constants.ATT_NULL_URI, "#" + certUri);
            attributes.put(Constants.ATT_NULL_ValueType, Constants.NS_X509_V3_TYPE);
            createStartElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_wsse_Reference, attributes);

            attributes = new HashMap<QName, String>();
            attributes.put(Constants.ATT_NULL_EncodingType, Constants.SOAPMESSAGE_NS10_BASE64_ENCODING);
            attributes.put(Constants.ATT_NULL_ValueType, Constants.NS_X509_V3_TYPE);
            attributes.put(Constants.ATT_wsu_Id, certUri);
            createStartElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_wsse_BinarySecurityToken, attributes);
            try {
                createCharactersAndOutputAsEvent(subOutputProcessorChain, new Base64(76, new byte[]{'\n'}).encodeToString(x509Certificate.getEncoded()));
            } catch (CertificateEncodingException e) {
                throw new WSSecurityException(WSSecurityException.FAILED_ENCRYPTION, null, e);
            }
            createEndElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_wsse_BinarySecurityToken);
            createEndElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_wsse_Reference);
        } else if (getSecurityProperties().getEncryptionKeyIdentifierType() == Constants.KeyIdentifierType.BST_DIRECT_REFERENCE) {

            attributes = new HashMap<QName, String>();
            attributes.put(Constants.ATT_NULL_URI, "#" + certUri);
            attributes.put(Constants.ATT_NULL_ValueType, referencedBinarySecurityTokenType.getValueType());
            createStartElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_wsse_Reference, attributes);
            createEndElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_wsse_Reference);
        } else {
            throw new WSSecurityException(WSSecurityException.FAILED_ENCRYPTION, "unsupportedSecurityToken", new Object[]{getSecurityProperties().getEncryptionKeyIdentifierType().name()});
        }

        createEndElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_wsse_SecurityTokenReference);
        createEndElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_dsig_KeyInfo);
        createStartElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_xenc_CipherData, null);
        createStartElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_xenc_CipherValue, null);

        try {
            //encrypt the symmetric session key with the public key from the receiver:
            String jceid = JCEAlgorithmMapper.translateURItoJCEID(getSecurityProperties().getEncryptionKeyTransportAlgorithm());
            Cipher cipher = Cipher.getInstance(jceid);
            cipher.init(Cipher.ENCRYPT_MODE, x509Certificate);

            byte[] ephemeralKey = symmetricKey.getEncoded();

            int blockSize = cipher.getBlockSize();
            if (blockSize > 0 && blockSize < ephemeralKey.length) {
                throw new WSSecurityException(WSSecurityException.FAILURE, "unsupportedKeyTransp", new Object[]{"public key algorithm too weak to encrypt symmetric key"}
                );
            }
            byte[] encryptedEphemeralKey = cipher.doFinal(ephemeralKey);

            createCharactersAndOutputAsEvent(subOutputProcessorChain, new Base64(76, new byte[]{'\n'}).encodeToString(encryptedEphemeralKey));

        } catch (NoSuchPaddingException e) {
            throw new WSSecurityException(WSSecurityException.FAILED_ENCRYPTION, null, e);
        } catch (NoSuchAlgorithmException e) {
            throw new WSSecurityException(WSSecurityException.FAILED_ENCRYPTION, null, e);
        } catch (InvalidKeyException e) {
            throw new WSSecurityException(WSSecurityException.FAILED_ENCRYPTION, null, e);
        } catch (BadPaddingException e) {
            throw new WSSecurityException(WSSecurityException.FAILED_ENCRYPTION, null, e);
        } catch (IllegalBlockSizeException e) {
            throw new WSSecurityException(WSSecurityException.FAILED_ENCRYPTION, null, e);
        }

        createEndElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_xenc_CipherValue);
        createEndElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_xenc_CipherData);

        createStartElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_xenc_ReferenceList, null);

        //output the references to the encrypted data:
        Iterator<EncryptionPartDef> encryptionPartDefIterator = encryptionPartDefList.iterator();
        while (encryptionPartDefIterator.hasNext()) {
            EncryptionPartDef encryptionPartDef = encryptionPartDefIterator.next();

            attributes = new HashMap<QName, String>();
            attributes.put(Constants.ATT_NULL_URI, "#" + encryptionPartDef.getEncRefId());
            createStartElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_xenc_DataReference, attributes);
            createEndElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_xenc_DataReference);
        }

        createEndElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_xenc_ReferenceList);
        createEndElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_xenc_EncryptedKey);

        /*
       <xenc:EncryptedKey xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" Id="EncKeyId-1483925398">
           <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-1_5" />
           <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
               <wsse:SecurityTokenReference xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
                   <wsse:KeyIdentifier EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary" ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509SubjectKeyIdentifier">
                       pHoiKNGY2YsLBKxwIV+jURt858M=
                   </wsse:KeyIdentifier>
               </wsse:SecurityTokenReference>
           </ds:KeyInfo>
           <xenc:CipherData>
               <xenc:CipherValue>
                   Khsa9SN3ALNXOgGDKOqihvfwGsXb9QN/q4Fpi9uuThgz+3D4oRSMkrGSPCqwG13vddvHywGAA/XNbWNT+5Xivz3lURCDCc2H/92YlXXo/crQNJnPlLrLZ81bGOzbNo7lnYQBLp/77K7b1bhldZAeV9ZfEW7DjbOMZ+k1dnDCu3A=
               </xenc:CipherValue>
           </xenc:CipherData>
           <xenc:ReferenceList>
               <xenc:DataReference URI="#EncDataId-1612925417" />
           </xenc:ReferenceList>
       </xenc:EncryptedKey>
        */
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
                        return x509SecurityToken.getX509Certificate();
                    }
                }
            }
        }
        return null;
    }
}
