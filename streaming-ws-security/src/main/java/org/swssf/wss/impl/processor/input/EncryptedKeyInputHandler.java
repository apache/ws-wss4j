/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.swssf.wss.impl.processor.input;

import org.swssf.binding.wss10.ObjectFactory;
import org.swssf.binding.wss10.ReferenceType;
import org.swssf.binding.wss10.SecurityTokenReferenceType;
import org.swssf.binding.xmldsig.KeyInfoType;
import org.swssf.binding.xmlenc.EncryptedKeyType;
import org.swssf.wss.ext.WSSConstants;
import org.swssf.wss.ext.WSSSecurityProperties;
import org.swssf.wss.ext.WSSecurityContext;
import org.swssf.wss.ext.WSSecurityException;
import org.swssf.wss.impl.securityToken.AbstractAlgorithmSuiteSecurityEventFiringSecurityToken;
import org.swssf.wss.impl.securityToken.SecurityTokenFactoryImpl;
import org.swssf.wss.securityEvent.EncryptionTokenSecurityEvent;
import org.swssf.wss.securityEvent.SecurityEvent;
import org.swssf.xmlsec.config.JCEAlgorithmMapper;
import org.swssf.xmlsec.crypto.Crypto;
import org.swssf.xmlsec.ext.*;
import org.xmlsecurity.ns.configuration.AlgorithmType;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.JAXBElement;
import javax.xml.stream.events.XMLEvent;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.*;

/**
 * Processor for the EncryptedKey XML Structure
 *
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class EncryptedKeyInputHandler extends AbstractInputSecurityHeaderHandler {

    public EncryptedKeyInputHandler(final InputProcessorChain inputProcessorChain,
                                    final WSSSecurityProperties securityProperties,
                                    Deque<XMLEvent> eventQueue, Integer index) throws XMLSecurityException {

        @SuppressWarnings("unchecked")
        final EncryptedKeyType encryptedKeyType = ((JAXBElement<EncryptedKeyType>) parseStructure(eventQueue, index)).getValue();
        if (encryptedKeyType.getId() == null) {
            encryptedKeyType.setId(UUID.randomUUID().toString());
        }

        SecurityTokenProvider securityTokenProvider = new SecurityTokenProvider() {

            private Map<Crypto, SecurityToken> securityTokens = new HashMap<Crypto, SecurityToken>();

            public SecurityToken getSecurityToken(Crypto crypto) throws XMLSecurityException {

                SecurityToken securityToken = securityTokens.get(crypto);
                if (securityToken != null) {
                    return securityToken;
                }

                //decrypt the containing token and register it as a new SecurityToken:
                String algorithmURI = null;
                final SecurityToken wrappingSecurityToken;
                final byte[] secretToken;
                try {
                    algorithmURI = encryptedKeyType.getEncryptionMethod().getAlgorithm();
                    if (algorithmURI == null) {
                        throw new WSSecurityException(WSSecurityException.ErrorCode.UNSUPPORTED_ALGORITHM, "noEncAlgo");
                    }
                    AlgorithmType asyncEncAlgo = JCEAlgorithmMapper.getAlgorithmMapping(algorithmURI);
                    Cipher cipher = Cipher.getInstance(asyncEncAlgo.getJCEName(), asyncEncAlgo.getJCEProvider());

                    KeyInfoType keyInfoType = encryptedKeyType.getKeyInfo();
                    wrappingSecurityToken = SecurityTokenFactoryImpl.newInstance().getSecurityToken(
                            keyInfoType,
                            crypto,
                            securityProperties.getCallbackHandler(),
                            inputProcessorChain.getSecurityContext(),
                            this
                    );
                    cipher.init(Cipher.DECRYPT_MODE, wrappingSecurityToken.getSecretKey(algorithmURI, wrappingSecurityToken.isAsymmetric() ? WSSConstants.Asym_Key_Wrap : WSSConstants.Sym_Key_Wrap));

                    secretToken = cipher.doFinal(encryptedKeyType.getCipherData().getCipherValue());

                } catch (NoSuchPaddingException e) {
                    throw new WSSecurityException(
                            WSSecurityException.ErrorCode.UNSUPPORTED_ALGORITHM, "unsupportedKeyTransp",
                            e, "No such padding: " + algorithmURI
                    );
                } catch (NoSuchAlgorithmException e) {
                    throw new WSSecurityException(
                            WSSecurityException.ErrorCode.UNSUPPORTED_ALGORITHM, "unsupportedKeyTransp",
                            e, "No such algorithm: " + algorithmURI
                    );
                } catch (BadPaddingException e) {
                    throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_CHECK, e);
                } catch (IllegalBlockSizeException e) {
                    throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_CHECK, e);
                } catch (InvalidKeyException e) {
                    throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_CHECK, e);
                } catch (NoSuchProviderException e) {
                    throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "noSecProvider", e);
                }

                final String algorithm = algorithmURI;

                securityToken = new AbstractAlgorithmSuiteSecurityEventFiringSecurityToken(inputProcessorChain.getSecurityContext(), encryptedKeyType.getId()) {

                    private Map<String, Key> keyTable = new Hashtable<String, Key>();

                    public boolean isAsymmetric() {
                        return false;
                    }

                    public Key getSecretKey(String algorithmURI, XMLSecurityConstants.KeyUsage keyUsage) throws XMLSecurityException {
                        super.getSecretKey(algorithmURI, keyUsage);
                        if (keyTable.containsKey(algorithmURI)) {
                            return keyTable.get(algorithmURI);
                        } else {
                            String algoFamily = JCEAlgorithmMapper.getJCERequiredKeyFromURI(algorithmURI);
                            Key key = new SecretKeySpec(secretToken, algoFamily);
                            keyTable.put(algorithmURI, key);
                            return key;
                        }
                    }

                    public SecurityToken getKeyWrappingToken() {
                        return wrappingSecurityToken;
                    }

                    public String getKeyWrappingTokenAlgorithm() {
                        return algorithm;
                    }

                    public WSSConstants.TokenType getTokenType() {
                        return WSSConstants.EncryptedKeyToken;
                    }
                };
                securityTokens.put(crypto, securityToken);
                return securityToken;
            }

            public String getId() {
                return encryptedKeyType.getId();
            }
        };

        final SecurityToken securityToken = securityTokenProvider.getSecurityToken(securityProperties.getDecryptionCrypto());
        //fire a RecipientSecurityTokenEvent
        EncryptionTokenSecurityEvent encryptionTokenSecurityEvent =
                new EncryptionTokenSecurityEvent(SecurityEvent.Event.EncryptionToken);

        encryptionTokenSecurityEvent.setSecurityToken(securityToken.getKeyWrappingToken());
        ((WSSecurityContext) inputProcessorChain.getSecurityContext()).registerSecurityEvent(encryptionTokenSecurityEvent);

        //register the key token for decryption:
        inputProcessorChain.getSecurityContext().registerSecurityTokenProvider(encryptedKeyType.getId(), securityTokenProvider);

        //if this EncryptedKey structure contains a reference list, instantiate a new DecryptInputProcessor
        //and add it to the chain
        if (encryptedKeyType.getReferenceList() != null) {
            KeyInfoType keyInfoType = new KeyInfoType();
            SecurityTokenReferenceType securityTokenReferenceType = new SecurityTokenReferenceType();
            ReferenceType referenceType = new ReferenceType();
            referenceType.setURI("#" + encryptedKeyType.getId());
            ObjectFactory objectFactory = new ObjectFactory();
            securityTokenReferenceType.getAny().add(objectFactory.createReference(referenceType));
            keyInfoType.getContent().add(objectFactory.createSecurityTokenReference(securityTokenReferenceType));
            inputProcessorChain.addProcessor(new org.swssf.wss.impl.processor.input.DecryptInputProcessor(keyInfoType, encryptedKeyType.getReferenceList(), securityProperties));
        }
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
