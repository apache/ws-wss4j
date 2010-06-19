package ch.gigerstyle.xmlsec.processorImpl.input;

import ch.gigerstyle.xmlsec.*;
import ch.gigerstyle.xmlsec.Base64;
import ch.gigerstyle.xmlsec.config.JCEAlgorithmMapper;
import ch.gigerstyle.xmlsec.crypto.WSSecurityException;
import org.bouncycastle.util.encoders.*;
import org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_secext_1_0.KeyIdentifierType;
import org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_secext_1_0.SecurityTokenReferenceType;
import org.w3._2000._09.xmldsig_.KeyInfoType;
import org.w3._2000._09.xmldsig_.X509DataType;
import org.w3._2000._09.xmldsig_.X509IssuerSerialType;
import org.w3._2001._04.xmlenc_.*;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.*;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

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
public class EncryptedKeyInputProcessor extends AbstractInputProcessor {

    private Map<String, EncryptedKeyType> encryptedKeys = new HashMap<String, EncryptedKeyType>();
    private EncryptedKeyType currentEncryptedKeyType;
    private KeyIdentifierType currentKeyIdentifierType;

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

        if (xmlEvent.isStartElement()) {
            StartElement startElement = xmlEvent.asStartElement();

            if (startElement.getName().equals(Constants.TAG_xmlenc_EncryptedKey)) {
                currentEncryptedKeyType = new EncryptedKeyType();

                Attribute attribute = startElement.getAttributeByName(Constants.ATT_NULL_Id);
                if (attribute != null) {
                    currentEncryptedKeyType.setId(attribute.getValue());
                    encryptedKeys.put(attribute.getValue(), currentEncryptedKeyType);
                } else {
                    encryptedKeys.put(null, currentEncryptedKeyType);
                }
            }
            else if (currentEncryptedKeyType == null) {
                //do nothing...fall out
            }
            else if (startElement.getName().equals(Constants.TAG_xmlenc_EncryptionMethod)) {

                //required:
                Attribute attribute = startElement.getAttributeByName(Constants.ATT_NULL_Algorithm);
                if (attribute == null) {
                    throw new XMLSecurityException("Missing Attribute " + Constants.ATT_NULL_Algorithm);
                }

                EncryptionMethodType encryptionMethodType = new EncryptionMethodType();
                encryptionMethodType.setAlgorithm(attribute.getValue());
                currentEncryptedKeyType.setEncryptionMethod(encryptionMethodType);
            }
            else if (startElement.getName().equals(Constants.TAG_dsig_KeyInfo)) {
                KeyInfoType keyInfoType = new KeyInfoType();
                //optional:
                Attribute idAttribute = startElement.getAttributeByName(Constants.ATT_NULL_Id);
                if (idAttribute != null) {
                    keyInfoType.setId(idAttribute.getValue());
                }
                currentEncryptedKeyType.setKeyInfo(keyInfoType);
            }
            else if (startElement.getName().equals(Constants.TAG_wsse_SecurityTokenReference)) {
                SecurityTokenReferenceType securityTokenReferenceType = new SecurityTokenReferenceType();
                //optional:
                Attribute idAttribute = startElement.getAttributeByName(Constants.ATT_wsu_Id);
                if (idAttribute != null) {
                    securityTokenReferenceType.setId(idAttribute.getValue());
                }
                currentEncryptedKeyType.getKeyInfo().getContent().add(securityTokenReferenceType);
            }
            else if (startElement.getName().equals(Constants.TAG_wsse_KeyIdentifier)) {
                KeyIdentifierType keyIdentifierType = new KeyIdentifierType();

                Attribute encodingType = startElement.getAttributeByName(Constants.ATT_NULL_EncodingType);
                if (encodingType != null) {
                    keyIdentifierType.setEncodingType(encodingType.getValue());
                }

                Attribute valueType = startElement.getAttributeByName(Constants.ATT_NULL_ValueType);
                if (valueType != null) {
                    keyIdentifierType.setValueType(valueType.getValue());
                }
                //todo easier api for lists with unknown types @see cxf
                ((SecurityTokenReferenceType)currentEncryptedKeyType.getKeyInfo().getContent().get(0)).getAny().add(keyIdentifierType);
                currentKeyIdentifierType = keyIdentifierType;
            }
            else if (startElement.getName().equals(Constants.TAG_xenc_CipherData)) {
                CipherDataType cipherDataType = new CipherDataType();
                currentEncryptedKeyType.setCipherData(cipherDataType);
            }
            else if (startElement.getName().equals(Constants.TAG_xenc_CipherValue)) {
                //nothing todo
            }
            else if (startElement.getName().equals(Constants.TAG_xenc_ReferenceList)) {
                ReferenceList referenceList = new ReferenceList();
                currentEncryptedKeyType.setReferenceList(referenceList);
            }
            else if (startElement.getName().equals(Constants.TAG_xenc_DataReference)) {

                Attribute uriAttribute = startElement.getAttributeByName(Constants.ATT_NULL_URI);
                if (uriAttribute == null) {
                    throw new XMLSecurityException("Missing Attribute " + Constants.ATT_NULL_URI);
                }
                ReferenceType referenceType = new ReferenceType();
                referenceType.setURI(Utils.dropReferenceMarker(uriAttribute.getValue()));
                currentEncryptedKeyType.getReferenceList().getDataReferenceOrKeyReference().add(referenceType);
            }
        }
        else if (currentEncryptedKeyType != null && xmlEvent.isCharacters()) {
            //todo handle multiple character events for same text-node
            Characters characters = xmlEvent.asCharacters();
            if (!characters.isWhiteSpace() &&getLastStartElementName().equals(Constants.TAG_xenc_CipherValue)) {
                currentEncryptedKeyType.getCipherData().setCipherValue(characters.getData().getBytes());
            }
            else if (!characters.isWhiteSpace() &&getLastStartElementName().equals(Constants.TAG_wsse_KeyIdentifier)) {
                currentKeyIdentifierType.setValue(characters.getData());
            }
        }
        else if (currentEncryptedKeyType != null && xmlEvent.isEndElement()) {
            EndElement endElement = xmlEvent.asEndElement();
            
            if (endElement.getName().equals(Constants.TAG_xmlenc_EncryptedKey)) {

                try {
                String asyncEncAlgo = JCEAlgorithmMapper.translateURItoJCEID(currentEncryptedKeyType.getEncryptionMethod().getAlgorithm());
                    Cipher cipher = Cipher.getInstance(asyncEncAlgo, "BC");

                    String alias = null;

                    KeyInfoType keyInfoType = currentEncryptedKeyType.getKeyInfo();
                    if (keyInfoType != null) {

                        //todo better access and null checks
                        SecurityTokenReferenceType securityTokenReferenceType = (SecurityTokenReferenceType)keyInfoType.getContent().get(0);
                        if (securityTokenReferenceType == null) {
                            throw new XMLSecurityException("No SecurityTokenReference found");
                        }

                        Object securityToken = securityTokenReferenceType.getAny().get(0);
                        if (securityToken == null) {
                            throw new XMLSecurityException("No securityToken found");
                        }
                        else if (securityToken instanceof X509DataType) {
                            X509DataType x509DataType = (X509DataType)securityToken;
                            //todo
                        } else if (securityToken instanceof X509IssuerSerialType) {
                            X509IssuerSerialType x509IssuerSerialType = (X509IssuerSerialType)securityToken;
                            //todo
                        }
                        else if (securityToken instanceof KeyIdentifierType) {
                            KeyIdentifierType keyIdentifierType = (KeyIdentifierType)securityToken;

                            String valueType = keyIdentifierType.getValueType();
                            byte[] binaryContent = org.bouncycastle.util.encoders.Base64.decode(keyIdentifierType.getValue());

                            if (Constants.X509_V3_TYPE.equals(valueType)) {
                                X509Certificate[] x509Certificate = getSecurityProperties().getDecryptionCrypto().getX509Certificates(binaryContent, false);
                                if (x509Certificate == null || x509Certificate.length < 1 || x509Certificate[0] == null) {
                                    throw new XMLSecurityException("noCertsFound" + "decryption (KeyId)");
                                }
                                alias = getSecurityProperties().getDecryptionCrypto().getAliasForX509Cert(x509Certificate[0]);
                            }
                            else if (Constants.SKI_URI.equals(valueType)) {
                                alias = getSecurityProperties().getDecryptionCrypto().getAliasForX509Cert(binaryContent);
                            }
                            else if (Constants.THUMB_URI.equals(valueType)) {
                                alias = getSecurityProperties().getDecryptionCrypto().getAliasForX509CertThumb(binaryContent);
                            }
                        }
                        else if (securityToken instanceof org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_secext_1_0.ReferenceType) {
                            org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_secext_1_0.ReferenceType referenceType
                                    = (org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_secext_1_0.ReferenceType)securityToken;
                            //todo
                        }
                    }
                    else if (getSecurityProperties().getDecryptionDefaultAlias() != null) {
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
                    cipher.init(Cipher.DECRYPT_MODE, privateKey);

                    byte[] encryptedEphemeralKey = org.bouncycastle.util.encoders.Base64.decode(currentEncryptedKeyType.getCipherData().getCipherValue());
                    byte[] decryptedKey = cipher.doFinal(encryptedEphemeralKey);

                inputProcessorChain.addProcessor(new DecryptInputProcessor(currentEncryptedKeyType, decryptedKey, getSecurityProperties()));
            } catch (NoSuchPaddingException e) {
                    throw new XMLSecurityException(e);
                } catch (WSSecurityException e) {
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
                    //probably we can remove this processor from the chain now?
                    currentEncryptedKeyType = null;
                }
            }
        }

        inputProcessorChain.processEvent(xmlEvent);
    }
}
