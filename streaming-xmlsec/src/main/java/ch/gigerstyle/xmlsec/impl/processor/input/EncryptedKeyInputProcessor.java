package ch.gigerstyle.xmlsec.impl.processor.input;

import ch.gigerstyle.xmlsec.config.JCEAlgorithmMapper;
import ch.gigerstyle.xmlsec.crypto.Crypto;
import ch.gigerstyle.xmlsec.ext.*;
import ch.gigerstyle.xmlsec.impl.SecurityTokenFactory;
import org.w3._2000._09.xmldsig_.KeyInfoType;
import org.w3._2001._04.xmlenc_.EncryptedKeyType;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;
import java.security.*;
import java.util.Hashtable;

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

    private EncryptedKeyType currentEncryptedKeyType;
    private boolean isFinishedcurrentEncryptedKey = false;

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

    @Override
    public void processSecurityHeaderEvent(XMLEvent xmlEvent, InputProcessorChain inputProcessorChain, SecurityContext securityContext) throws XMLStreamException, XMLSecurityException {
        if (currentEncryptedKeyType != null) {
            try {
                isFinishedcurrentEncryptedKey = currentEncryptedKeyType.parseXMLEvent(xmlEvent);
                if (isFinishedcurrentEncryptedKey) {
                    currentEncryptedKeyType.validate();
                }
            } catch (ParseException e) {
                throw new XMLSecurityException(e);
            }
        } else if (xmlEvent.isStartElement()) {
            StartElement startElement = xmlEvent.asStartElement();
            if (startElement.getName().equals(Constants.TAG_xenc_EncryptedKey)) {
                currentEncryptedKeyType = new EncryptedKeyType(startElement);
            }
        }

        if (currentEncryptedKeyType != null && isFinishedcurrentEncryptedKey) {

            try {
                final String algorithmURI = currentEncryptedKeyType.getEncryptionMethod().getAlgorithm();
                String asyncEncAlgo = JCEAlgorithmMapper.translateURItoJCEID(algorithmURI);
                Cipher cipher = Cipher.getInstance(asyncEncAlgo, "BC");

                KeyInfoType keyInfoType = currentEncryptedKeyType.getKeyInfo();
                final SecurityToken securityToken = SecurityTokenFactory.newInstance().getSecurityToken(keyInfoType, getSecurityProperties().getDecryptionCrypto(), getSecurityProperties().getCallbackHandler(), securityContext);
                cipher.init(Cipher.DECRYPT_MODE, securityToken.getSecretKey(algorithmURI));

                byte[] encryptedEphemeralKey = org.bouncycastle.util.encoders.Base64.decode(currentEncryptedKeyType.getCipherData().getCipherValue());
                final byte[] secretToken = cipher.doFinal(encryptedEphemeralKey);

                if (currentEncryptedKeyType.getId() != null) {

                    SecurityTokenProvider securityTokenProvider = new SecurityTokenProvider() {

                        public SecurityToken getSecurityToken(Crypto crypto) throws XMLSecurityException {
                            
                            return new SecurityToken() {

                                private Hashtable<String, Key> keyTable = new Hashtable<String, Key>();

                                public boolean isAsymmetric() {
                                    return false;
                                }

                                public Key getSecretKey(String algorithmURI) throws XMLSecurityException {
                                    if (keyTable.containsKey(algorithmURI)) {
                                        return keyTable.get(algorithmURI);
                                    } else {
                                        String algoFamily = JCEAlgorithmMapper.getJCEKeyAlgorithmFromURI(algorithmURI);
                                        Key key = new SecretKeySpec(secretToken, algoFamily);
                                        keyTable.put(algorithmURI, key);
                                        return key; 
                                    }
                                }

                                public PublicKey getPublicKey() throws XMLSecurityException {
                                    return null;
                                }

                                public void verify() throws XMLSecurityException {
                                }

                                public SecurityToken getKeyWrappingToken() {
                                    return securityToken; 
                                }

                                public String getKeyWrappingTokenAlgorithm() {
                                    return algorithmURI;
                                }

                                public Constants.KeyIdentifierType getKeyIdentifierType() {
                                    return Constants.KeyIdentifierType.BST_EMBEDDED;
                                }
                            };
                        }
                    };

                    securityContext.registerSecurityTokenProvider(currentEncryptedKeyType.getId(), securityTokenProvider);
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

        inputProcessorChain.processSecurityHeaderEvent(xmlEvent);
    }

    @Override
    public void processEvent(XMLEvent xmlEvent, InputProcessorChain inputProcessorChain, SecurityContext securityContext) throws XMLStreamException, XMLSecurityException {
        //this method should not be called (processor will be removed after processing header
        inputProcessorChain.processEvent(xmlEvent);
    }
}
