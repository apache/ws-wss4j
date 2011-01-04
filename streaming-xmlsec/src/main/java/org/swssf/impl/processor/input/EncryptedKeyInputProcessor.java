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
package org.swssf.impl.processor.input;

import org.swssf.config.JCEAlgorithmMapper;
import org.swssf.crypto.Crypto;
import org.swssf.ext.*;
import org.swssf.impl.SecurityTokenFactory;
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
 * Prozessor for the EncryptedKey XML Structure
 * @author $Author: giger $
 * @version $Revision: 281 $ $Date: 2011-01-04 21:15:27 +0100 (Tue, 04 Jan 2011) $
 */
public class EncryptedKeyInputProcessor extends AbstractInputProcessor {

    private EncryptedKeyType currentEncryptedKeyType;

    public EncryptedKeyInputProcessor(SecurityProperties securityProperties, StartElement startElement) {
        super(securityProperties);
        currentEncryptedKeyType = new EncryptedKeyType(startElement);
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
    public XMLEvent processNextHeaderEvent(InputProcessorChain inputProcessorChain) throws XMLStreamException, XMLSecurityException {
        XMLEvent xmlEvent = inputProcessorChain.processHeaderEvent();

        //parse the EncryptedKey XML Structure
        //this is ugly and will be replaced with a better implementation
        boolean isFinishedcurrentEncryptedKey = false;

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

        if (currentEncryptedKeyType != null && isFinishedcurrentEncryptedKey) {
            //decrypt the containing token and register it as a new SecurityToken:
            try {
                final String algorithmURI = currentEncryptedKeyType.getEncryptionMethod().getAlgorithm();
                String asyncEncAlgo = JCEAlgorithmMapper.translateURItoJCEID(algorithmURI);
                Cipher cipher = Cipher.getInstance(asyncEncAlgo, "BC");

                KeyInfoType keyInfoType = currentEncryptedKeyType.getKeyInfo();
                final SecurityToken securityToken = SecurityTokenFactory.newInstance().getSecurityToken(keyInfoType, getSecurityProperties().getDecryptionCrypto(), getSecurityProperties().getCallbackHandler(), inputProcessorChain.getSecurityContext());
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
                    //register the key token for decryption:
                    inputProcessorChain.getSecurityContext().registerSecurityTokenProvider(currentEncryptedKeyType.getId(), securityTokenProvider);
                }

                //if this EncryptedKey structure contains a reference list, instantiate a new DecryptInputProcessor
                //and add it to the chain
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
            }
        }

        return xmlEvent;
    }

    @Override
    public XMLEvent processNextEvent(InputProcessorChain inputProcessorChain) throws XMLStreamException, XMLSecurityException {
        //this method should not be called (processor will be removed after processing header
        return null;
    }
}
