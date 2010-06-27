package ch.gigerstyle.xmlsec.processorImpl.input;

import ch.gigerstyle.xmlsec.*;
import ch.gigerstyle.xmlsec.config.JCEAlgorithmMapper;
import ch.gigerstyle.xmlsec.crypto.Crypto;
import ch.gigerstyle.xmlsec.crypto.WSSecurityException;
import org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_secext_1_0.BinarySecurityTokenType;
import org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_secext_1_0.KeyIdentifierType;
import org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_secext_1_0.SecurityTokenReferenceType;
import org.w3._2000._09.xmldsig_.KeyInfoType;
import org.w3._2000._09.xmldsig_.X509DataType;
import org.w3._2001._04.xmlenc_.EncryptedKeyType;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.X509Certificate;

/**
 * User: giger
 * Date: May 13, 2010
 * Time: 1:42:42 PM
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
public class EncryptedKeyInputProcessor extends AbstractInputProcessor implements SecurityTokenProvider {

    private EncryptedKeyType currentEncryptedKeyType;
    private boolean isFinishedcurrentEncryptedKey = false;

    private byte[] secretToken;

    public EncryptedKeyInputProcessor(SecurityProperties securityProperties) {
        super(securityProperties);
    }

    /*
    <xenc:EncryptedKey xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" Id="EncKeyId-1483925398">
        <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-1_5" />
        <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
            <wsse:SecurityTokenReference xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
                <wsse:KeyIdentifier EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary"
                    ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509SubjectKeyIdentifier">pHoiKNGY2YsLBKxwIV+jURt858M=</wsse:KeyIdentifier>
                </wsse:SecurityTokenReference>
        </ds:KeyInfo>
        <xenc:CipherData>
            <xenc:CipherValue>Khsa9SN3ALNXOgGDKOqihvfwGsXb9QN/q4Fpi9uuThgz+3D4oRSMkrGSPCqwG13vddvHywGAA/XNbWNT+5Xivz3lURCDCc2H/92YlXXo/crQNJnPlLrLZ81bGOzbNo7lnYQBLp/77K7b1bhldZAeV9ZfEW7DjbOMZ+k1dnDCu3A=</xenc:CipherValue>
        </xenc:CipherData>
        <xenc:ReferenceList>
            <xenc:DataReference URI="#EncDataId-1612925417" />
        </xenc:ReferenceList>
    </xenc:EncryptedKey>
     */

    public void processEvent(XMLEvent xmlEvent, InputProcessorChain inputProcessorChain, SecurityContext securityContext) throws XMLStreamException, XMLSecurityException {

        if (currentEncryptedKeyType != null) {
            try {
                isFinishedcurrentEncryptedKey = currentEncryptedKeyType.parseXMLEvent(xmlEvent);
                if (isFinishedcurrentEncryptedKey) {
                    currentEncryptedKeyType.validate();
                }
            } catch (ParseException e) {
                throw new XMLSecurityException(e);
            }
        }
        else if (xmlEvent.isStartElement()) {
            StartElement startElement = xmlEvent.asStartElement();
            if (startElement.getName().equals(Constants.TAG_xenc_EncryptedKey)) {
                currentEncryptedKeyType = new EncryptedKeyType(startElement);
            }
        }

        if (currentEncryptedKeyType != null && isFinishedcurrentEncryptedKey) {

            try {
                String asyncEncAlgo = JCEAlgorithmMapper.translateURItoJCEID(currentEncryptedKeyType.getEncryptionMethod().getAlgorithm());
                Cipher cipher = Cipher.getInstance(asyncEncAlgo, "BC");

                String alias = null;

                KeyInfoType keyInfoType = currentEncryptedKeyType.getKeyInfo();
  /*              if (keyInfoType != null) {

                    SecurityTokenReferenceType securityTokenReferenceType = keyInfoType.getSecurityTokenReferenceType();
                    if (securityTokenReferenceType == null) {
                        throw new XMLSecurityException("No SecurityTokenReference found");
                    }

                    if (securityTokenReferenceType.getX509DataType() != null) {
                        X509DataType x509DataType = securityTokenReferenceType.getX509DataType();
                        alias = getSecurityProperties().getDecryptionCrypto().getAliasForX509Cert(x509DataType.getX509IssuerSerialType().getX509IssuerName(), x509DataType.getX509IssuerSerialType().getX509SerialNumber());
                    } *//*else if (securityToken instanceof X509IssuerSerialType) {
                        X509IssuerSerialType x509IssuerSerialType = (X509IssuerSerialType) securityToken;
                        //todo this is not supported by outputProcessor but can be implemented. We'll have a look at the spec if this is allowed
                    }*/ /*
                    else if (securityTokenReferenceType.getKeyIdentifierType() != null) {
                        KeyIdentifierType keyIdentifierType = securityTokenReferenceType.getKeyIdentifierType();

                        String valueType = keyIdentifierType.getValueType();
                        String encodingType = keyIdentifierType.getEncodingType();

                        byte[] binaryContent;
                        if (Constants.SOAPMESSAGE_NS10_BASE64_ENCODING.equals(encodingType)) {
                            binaryContent = org.bouncycastle.util.encoders.Base64.decode(keyIdentifierType.getValue());
                        } else {
                            binaryContent = keyIdentifierType.getValue().getBytes();
                        }

                        if (Constants.NS_X509_V3_TYPE.equals(valueType)) {
                            X509Certificate x509Certificate = getSecurityProperties().getDecryptionCrypto().loadCertificate(new ByteArrayInputStream(binaryContent));
                            if (x509Certificate == null) {
                                throw new XMLSecurityException("noCertsFound" + "decryption (KeyId)");
                            }
                            alias = getSecurityProperties().getDecryptionCrypto().getAliasForX509Cert(x509Certificate);
                        } else if (Constants.NS_X509SubjectKeyIdentifier.equals(valueType)) {
                            alias = getSecurityProperties().getDecryptionCrypto().getAliasForX509Cert(binaryContent);
                        } else if (Constants.NS_THUMBPRINT.equals(valueType)) {
                            alias = getSecurityProperties().getDecryptionCrypto().getAliasForX509CertThumb(binaryContent);
                        }
                    }//todo BST can be SAML Token, Custom-Token etc... 
                    else if (securityTokenReferenceType.getReferenceType() != null) {

                        String uri = securityTokenReferenceType.getReferenceType().getURI();
                        if (uri == null) {
                            throw new XMLSecurityException("badReferenceURI");
                        }
                        uri = Utils.dropReferenceMarker(uri);
                        if (securityTokenReferenceType.getReferenceType().getBinarySecurityTokenType() != null
                                && uri.equals(securityTokenReferenceType.getReferenceType().getBinarySecurityTokenType().getId())) {

                            BinarySecurityTokenType binarySecurityTokenType = securityTokenReferenceType.getReferenceType().getBinarySecurityTokenType();
                            if (!Constants.NS_X509_V3_TYPE.equals(binarySecurityTokenType.getValueType())) {
                                throw new XMLSecurityException("unsupportedBinaryTokenType");
                            }
                            byte[] binaryContent;
                            if (Constants.SOAPMESSAGE_NS10_BASE64_ENCODING.equals(binarySecurityTokenType.getEncodingType())) {
                                binaryContent = org.bouncycastle.util.encoders.Base64.decode(binarySecurityTokenType.getValue());
                            } else {
                                binaryContent = binarySecurityTokenType.getValue().getBytes();
                            }
                            X509Certificate x509Certificate = getSecurityProperties().getDecryptionCrypto().loadCertificate(new ByteArrayInputStream(binaryContent));
                            if (x509Certificate == null) {
                                throw new XMLSecurityException("noCertsFound" + "decryption (KeyId)");
                            }
                            alias = getSecurityProperties().getDecryptionCrypto().getAliasForX509Cert(x509Certificate);

                        } else {
                            //todo
                            //we have to search BST somewhere in the doc. First we will check for a BST already processed and
                            //stored in the context. Otherwise we will abort now.
                            throw new XMLSecurityException("No SecurityToken found");
                        }
                    } else {
                        throw new XMLSecurityException("No SecurityToken found");
                    }
                } else if (getSecurityProperties().getDecryptionDefaultAlias() != null) {
                    //todo
                } else {
                    throw new XMLSecurityException("No KeyInfo in request and no defaultAlias specified");
                }

                WSPasswordCallback pwCb = new WSPasswordCallback(alias, WSPasswordCallback.DECRYPT);
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

                PrivateKey privateKey = getSecurityProperties().getDecryptionCrypto().getPrivateKey(alias, password);
*/
                SecurityToken securityToken = SecurityTokenFactory.newInstance().getSecurityToken(keyInfoType, getSecurityProperties().getDecryptionCrypto(), getSecurityProperties().getCallbackHandler(), securityContext);
                cipher.init(Cipher.DECRYPT_MODE, securityToken.getSecretKey());

                byte[] encryptedEphemeralKey = org.bouncycastle.util.encoders.Base64.decode(currentEncryptedKeyType.getCipherData().getCipherValue());
                secretToken = cipher.doFinal(encryptedEphemeralKey);

                if (currentEncryptedKeyType.getId() != null) {
                    securityContext.registerSecurityTokenProvider(currentEncryptedKeyType.getId(), this);
                }

                if (currentEncryptedKeyType.getReferenceList() != null) {
                    inputProcessorChain.addProcessor(new DecryptInputProcessor(currentEncryptedKeyType.getReferenceList(), getSecurityProperties()));
                }

            } catch (NoSuchPaddingException e) {
                throw new XMLSecurityException(e);
            } catch (NoSuchAlgorithmException e) {
                throw new XMLSecurityException(e);
            } catch (BadPaddingException e) {
                throw new XMLSecurityException(e);
            } catch (IllegalBlockSizeException e) {
                throw new XMLSecurityException(e);
            } catch (NoSuchProviderException e) {
                throw new XMLSecurityException(e);
            } catch (InvalidKeyException e) {
                throw new XMLSecurityException(e);
            } catch (Exception e) {
                throw new XMLSecurityException(e);
            }
            finally {
                inputProcessorChain.removeProcessor(this);
                currentEncryptedKeyType = null;
                isFinishedcurrentEncryptedKey = false;
            }
        }
        inputProcessorChain.processEvent(xmlEvent);
    }

    public SecurityToken getSecurityToken(Crypto crypto) throws XMLSecurityException {
        return new SecurityToken() {

            public byte[] getSymmetricKey() throws XMLSecurityException {
                return secretToken;
            }

            public Key getSecretKey() throws XMLSecurityException {
                return null;
            }

            public PublicKey getPublicKey() throws XMLSecurityException {
                return null;
            }

            public void verify() throws XMLSecurityException {
            }
        };
    }
}
