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

import org.apache.commons.codec.binary.Base64;
import org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_secext_1_0.ReferenceType;
import org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_secext_1_0.SecurityTokenReferenceType;
import org.swssf.config.JCEAlgorithmMapper;
import org.swssf.crypto.Crypto;
import org.swssf.ext.*;
import org.swssf.impl.securityToken.SecurityTokenFactory;
import org.w3._2000._09.xmldsig_.KeyInfoType;
import org.w3._2001._04.xmlenc_.EncryptedKeyType;
import org.xmlsecurity.ns.configuration.AlgorithmType;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Deque;
import java.util.Hashtable;
import java.util.Map;

/**
 * Processor for the EncryptedKey XML Structure
 *
 * @author $Author: giger $
 * @version $Revision: 281 $ $Date: 2011-01-04 21:15:27 +0100 (Tue, 04 Jan 2011) $
 */
public class EncryptedKeyInputHandler extends AbstractInputSecurityHeaderHandler {

    public EncryptedKeyInputHandler(final InputProcessorChain inputProcessorChain, final SecurityProperties securityProperties, Deque<XMLEvent> eventQueue, Integer index) throws WSSecurityException {

        final EncryptedKeyType encryptedKeyType = (EncryptedKeyType) parseStructure(eventQueue, index);

        if (encryptedKeyType.getId() != null) {

            SecurityTokenProvider securityTokenProvider = new SecurityTokenProvider() {

                public SecurityToken getSecurityToken(Crypto crypto) throws WSSecurityException {

                    //decrypt the containing token and register it as a new SecurityToken:
                    String algorithmURI = null;
                    final SecurityToken securityToken;
                    final byte[] secretToken;
                    try {
                        algorithmURI = encryptedKeyType.getEncryptionMethod().getAlgorithm();
                        if (algorithmURI == null) {
                            throw new WSSecurityException(WSSecurityException.UNSUPPORTED_ALGORITHM, "noEncAlgo");
                        }
                        AlgorithmType asyncEncAlgo = JCEAlgorithmMapper.getAlgorithmMapping(algorithmURI);
                        Cipher cipher = Cipher.getInstance(asyncEncAlgo.getJCEName(), asyncEncAlgo.getJCEProvider());

                        KeyInfoType keyInfoType = encryptedKeyType.getKeyInfo();
                        securityToken = SecurityTokenFactory.newInstance().getSecurityToken(
                                keyInfoType,
                                crypto,
                                securityProperties.getCallbackHandler(),
                                inputProcessorChain.getSecurityContext()
                        );
                        cipher.init(Cipher.DECRYPT_MODE, securityToken.getSecretKey(algorithmURI));

                        byte[] encryptedEphemeralKey = Base64.decodeBase64(encryptedKeyType.getCipherData().getCipherValue());
                        secretToken = cipher.doFinal(encryptedEphemeralKey);

                    } catch (NoSuchPaddingException e) {
                        throw new WSSecurityException(
                                WSSecurityException.UNSUPPORTED_ALGORITHM, "unsupportedKeyTransp",
                                new Object[]{"No such padding: " + algorithmURI}, e
                        );
                    } catch (NoSuchAlgorithmException e) {
                        throw new WSSecurityException(
                                WSSecurityException.UNSUPPORTED_ALGORITHM, "unsupportedKeyTransp",
                                new Object[]{"No such algorithm: " + algorithmURI}, e
                        );
                    } catch (BadPaddingException e) {
                        throw new WSSecurityException(WSSecurityException.FAILED_CHECK, null, e);
                    } catch (IllegalBlockSizeException e) {
                        throw new WSSecurityException(WSSecurityException.FAILED_CHECK, null, e);
                    } catch (InvalidKeyException e) {
                        throw new WSSecurityException(WSSecurityException.FAILED_CHECK, null, e);
                    } catch (NoSuchProviderException e) {
                        throw new WSSecurityException(WSSecurityException.FAILURE, "noSecProvider", e);
                    }

                    final String algorithm = algorithmURI;

                    return new SecurityToken() {

                        private Map<String, Key> keyTable = new Hashtable<String, Key>();

                        public boolean isAsymmetric() {
                            return false;
                        }

                        public Key getSecretKey(String algorithmURI) throws WSSecurityException {
                            if (keyTable.containsKey(algorithmURI)) {
                                return keyTable.get(algorithmURI);
                            } else {
                                String algoFamily = JCEAlgorithmMapper.getJCEKeyAlgorithmFromURI(algorithmURI);
                                Key key = new SecretKeySpec(secretToken, algoFamily);
                                keyTable.put(algorithmURI, key);
                                return key;
                            }
                        }

                        public PublicKey getPublicKey() throws WSSecurityException {
                            return null;
                        }

                        public X509Certificate[] getX509Certificates() throws WSSecurityException {
                            return null;
                        }

                        public void verify() throws WSSecurityException {
                        }

                        public SecurityToken getKeyWrappingToken() {
                            return securityToken;
                        }

                        public String getKeyWrappingTokenAlgorithm() {
                            return algorithm;
                        }

                        public Constants.KeyIdentifierType getKeyIdentifierType() {
                            return Constants.KeyIdentifierType.BST_EMBEDDED;
                        }
                    };
                }

                public String getId() {
                    return encryptedKeyType.getId();
                }
            };
            //register the key token for decryption:
            inputProcessorChain.getSecurityContext().registerSecurityTokenProvider(encryptedKeyType.getId(), securityTokenProvider);
        }

        //if this EncryptedKey structure contains a reference list, instantiate a new DecryptInputProcessor
        //and add it to the chain
        if (encryptedKeyType.getReferenceList() != null) {
            KeyInfoType keyInfoType = new KeyInfoType();
            SecurityTokenReferenceType securityTokenReferenceType = new SecurityTokenReferenceType();
            ReferenceType referenceType = new ReferenceType();
            referenceType.setURI("#" + encryptedKeyType.getId());
            securityTokenReferenceType.setReferenceType(referenceType);
            keyInfoType.setSecurityTokenReferenceType(securityTokenReferenceType);
            inputProcessorChain.addProcessor(new DecryptInputProcessor(keyInfoType, encryptedKeyType.getReferenceList(), securityProperties));
        }
    }

    @Override
    protected Parseable getParseable(StartElement startElement) {
        return new EncryptedKeyType(startElement);
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
}
