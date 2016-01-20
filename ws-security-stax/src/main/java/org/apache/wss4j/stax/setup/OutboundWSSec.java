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
package org.apache.wss4j.stax.setup;

import java.io.OutputStream;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.stream.XMLStreamWriter;

import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoType;
import org.apache.wss4j.common.ext.WSPasswordCallback;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.ext.WSSSecurityProperties;
import org.apache.wss4j.stax.impl.processor.output.BinarySecurityTokenOutputProcessor;
import org.apache.wss4j.stax.impl.processor.output.CustomTokenOutputProcessor;
import org.apache.wss4j.stax.impl.processor.output.DerivedKeyTokenOutputProcessor;
import org.apache.wss4j.stax.impl.processor.output.EncryptEndingOutputProcessor;
import org.apache.wss4j.stax.impl.processor.output.EncryptOutputProcessor;
import org.apache.wss4j.stax.impl.processor.output.EncryptedKeyOutputProcessor;
import org.apache.wss4j.stax.impl.processor.output.ReferenceListOutputProcessor;
import org.apache.wss4j.stax.impl.processor.output.SAMLTokenOutputProcessor;
import org.apache.wss4j.stax.impl.processor.output.SecurityContextTokenOutputProcessor;
import org.apache.wss4j.stax.impl.processor.output.SecurityHeaderOutputProcessor;
import org.apache.wss4j.stax.impl.processor.output.SecurityHeaderReorderProcessor;
import org.apache.wss4j.stax.impl.processor.output.SignatureConfirmationOutputProcessor;
import org.apache.wss4j.stax.impl.processor.output.TimestampOutputProcessor;
import org.apache.wss4j.stax.impl.processor.output.UsernameTokenOutputProcessor;
import org.apache.wss4j.stax.impl.processor.output.WSSSignatureOutputProcessor;
import org.apache.wss4j.stax.impl.securityToken.KerberosClientSecurityToken;
import org.apache.wss4j.stax.securityToken.WSSecurityTokenConstants;
import org.apache.wss4j.stax.utils.WSSUtils;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.config.JCEAlgorithmMapper;
import org.apache.xml.security.stax.ext.OutboundSecurityContext;
import org.apache.xml.security.stax.ext.OutputProcessor;
import org.apache.xml.security.stax.ext.SecurityContext;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.impl.DocumentContextImpl;
import org.apache.xml.security.stax.impl.OutboundSecurityContextImpl;
import org.apache.xml.security.stax.impl.OutputProcessorChainImpl;
import org.apache.xml.security.stax.impl.XMLSecurityStreamWriter;
import org.apache.xml.security.stax.impl.processor.output.FinalOutputProcessor;
import org.apache.xml.security.stax.impl.securityToken.GenericOutboundSecurityToken;
import org.apache.xml.security.stax.impl.util.IDGenerator;
import org.apache.xml.security.stax.securityEvent.SecurityEvent;
import org.apache.xml.security.stax.securityEvent.SecurityEventListener;
import org.apache.xml.security.stax.securityEvent.TokenSecurityEvent;
import org.apache.xml.security.stax.securityToken.OutboundSecurityToken;
import org.apache.xml.security.stax.securityToken.SecurityToken;
import org.apache.xml.security.stax.securityToken.SecurityTokenConstants.TokenUsage;
import org.apache.xml.security.stax.securityToken.SecurityTokenProvider;

/**
 * Outbound Streaming-WebService-Security
 * An instance of this class can be retrieved over the WSSec class
 */
public class OutboundWSSec {

    private final WSSSecurityProperties securityProperties;

    public OutboundWSSec(WSSSecurityProperties securityProperties) {
        this.securityProperties = securityProperties;
    }

    /**
     * This method is the entry point for the incoming security-engine.
     * Hand over a outputStream and use the returned XMLStreamWriter for further processing
     *
     * @param outputStream The original outputStream
     * @return A new XMLStreamWriter which does transparently the security processing.
     * @throws WSSecurityException thrown when a Security failure occurs
     */
    public XMLStreamWriter processOutMessage(
            OutputStream outputStream, String encoding,
            List<SecurityEvent> requestSecurityEvents) throws WSSecurityException {
        return processOutMessage(outputStream, encoding, requestSecurityEvents, null);
    }

    /**
     * This method is the entry point for the incoming security-engine.
     * Hand over the original XMLStreamWriter and use the returned one for further processing
     *
     * @param xmlStreamWriter The original xmlStreamWriter
     * @return A new XMLStreamWriter which does transparently the security processing.
     * @throws WSSecurityException thrown when a Security failure occurs
     */
    public XMLStreamWriter processOutMessage(
            XMLStreamWriter xmlStreamWriter, String encoding,
            List<SecurityEvent> requestSecurityEvents) throws WSSecurityException {
        return processOutMessage(xmlStreamWriter, encoding, requestSecurityEvents, null);
    }

    /**
     * This method is the entry point for the incoming security-engine.
     * Hand over a outputstream and use the returned XMLStreamWriter for further processing
     *
     * @param outputStream The original outputStream
     * @return A new XMLStreamWriter which does transparently the security processing.
     * @throws WSSecurityException thrown when a Security failure occurs
     */
    public XMLStreamWriter processOutMessage(
            OutputStream outputStream, String encoding, List<SecurityEvent> requestSecurityEvents,
            SecurityEventListener securityEventListener) throws WSSecurityException {
        final OutboundSecurityContextImpl outboundSecurityContext = new OutboundSecurityContextImpl();
        outboundSecurityContext.putList(SecurityEvent.class, requestSecurityEvents);
        outboundSecurityContext.addSecurityEventListener(securityEventListener);
        return processOutMessage((Object) outputStream, encoding, outboundSecurityContext);
    }

    /**
     * This method is the entry point for the incoming security-engine.
     * Hand over the original XMLStreamWriter and use the returned one for further processing
     *
     * @param xmlStreamWriter The original outputStream
     * @return A new XMLStreamWriter which does transparently the security processing.
     * @throws WSSecurityException thrown when a Security failure occurs
     */
    public XMLStreamWriter processOutMessage(
            XMLStreamWriter xmlStreamWriter, String encoding, List<SecurityEvent> requestSecurityEvents,
            SecurityEventListener securityEventListener) throws WSSecurityException {
        final OutboundSecurityContextImpl outboundSecurityContext = new OutboundSecurityContextImpl();
        outboundSecurityContext.putList(SecurityEvent.class, requestSecurityEvents);
        outboundSecurityContext.addSecurityEventListener(securityEventListener);
        return processOutMessage((Object) xmlStreamWriter, encoding, outboundSecurityContext);
    }

    /**
     * This method is the entry point for the incoming security-engine.
     * Hand over the original XMLStreamWriter and use the returned one for further processing
     *
     * @param xmlStreamWriter The original outputStream
     * @return A new XMLStreamWriter which does transparently the security processing.
     * @throws WSSecurityException thrown when a Security failure occurs
     */
    public XMLStreamWriter processOutMessage(
            XMLStreamWriter xmlStreamWriter, String encoding, OutboundSecurityContext outbounSecurityContext) 
                throws WSSecurityException {
        return processOutMessage((Object) xmlStreamWriter, encoding, outbounSecurityContext);
    }

    public XMLStreamWriter processOutMessage(
            Object output, String encoding, OutboundSecurityContext outboundSecurityContext
        ) throws WSSecurityException {

        final DocumentContextImpl documentContext = new DocumentContextImpl();
        documentContext.setEncoding(encoding);

        OutputProcessorChainImpl outputProcessorChain = new OutputProcessorChainImpl(outboundSecurityContext, documentContext);

        try {
            final SecurityHeaderOutputProcessor securityHeaderOutputProcessor = new SecurityHeaderOutputProcessor();
            initializeOutputProcessor(outputProcessorChain, securityHeaderOutputProcessor, null);
            
            ConfiguredAction configuredAction = configureActions(outputProcessorChain);
            
            // Set up appropriate keys
            if (configuredAction.signatureAction) {
                setupSignatureKey(outputProcessorChain, securityProperties, configuredAction.signedSAML);
            }
            if (configuredAction.encryptionAction) {
                setupEncryptionKey(outputProcessorChain, securityProperties);
            }
            if (configuredAction.kerberos) {
                setupKerberosKey(outputProcessorChain, securityProperties,
                                 configuredAction.signatureKerberos, configuredAction.encryptionKerberos);
            }
            if (configuredAction.derivedSignature) {
                String id =
                    outputProcessorChain.getSecurityContext().get(WSSConstants.PROP_USE_THIS_TOKEN_ID_FOR_SIGNATURE);
                setDerivedIdentifier(outputProcessorChain, id);
            }
            if (configuredAction.derivedEncryption) {
                String id =
                    outputProcessorChain.getSecurityContext().get(WSSConstants.PROP_USE_THIS_TOKEN_ID_FOR_ENCRYPTED_KEY);
                if (id == null) {
                    // Maybe not encrypting the key here...
                    id = outputProcessorChain.getSecurityContext().get(WSSConstants.PROP_USE_THIS_TOKEN_ID_FOR_ENCRYPTION);
                }
                setDerivedIdentifier(outputProcessorChain, id);
            }

            final SecurityHeaderReorderProcessor securityHeaderReorderProcessor = new SecurityHeaderReorderProcessor();
            initializeOutputProcessor(outputProcessorChain, securityHeaderReorderProcessor, null);

            if (output instanceof OutputStream) {
                final FinalOutputProcessor finalOutputProcessor = new FinalOutputProcessor((OutputStream) output, encoding);
                initializeOutputProcessor(outputProcessorChain, finalOutputProcessor, null);

            } else if (output instanceof XMLStreamWriter) {
                final FinalOutputProcessor finalOutputProcessor = new FinalOutputProcessor((XMLStreamWriter) output);
                initializeOutputProcessor(outputProcessorChain, finalOutputProcessor, null);

            } else {
                throw new IllegalArgumentException(output + " is not supported as output");
            }
        } catch (XMLSecurityException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, e);
        }
        return new XMLSecurityStreamWriter(outputProcessorChain);
    }

    private void initializeOutputProcessor(
            OutputProcessorChainImpl outputProcessorChain, OutputProcessor outputProcessor,
            XMLSecurityConstants.Action action) throws XMLSecurityException {
        outputProcessor.setXMLSecurityProperties(securityProperties);
        outputProcessor.setAction(action);
        outputProcessor.init(outputProcessorChain);
    }

    private void setupSignatureKey(
        OutputProcessorChainImpl outputProcessorChain,
        WSSSecurityProperties securityProperties,
        boolean signedSAML
    ) throws XMLSecurityException {
        final String signatureAlgorithm = securityProperties.getSignatureAlgorithm();

        GenericOutboundSecurityToken securityToken =
            getOutboundSecurityToken(outputProcessorChain, WSSConstants.PROP_USE_THIS_TOKEN_ID_FOR_SIGNATURE);
        // First off, see if we have a supplied token with the correct keys for
        // (a)symmetric signature
        if (securityToken != null && signatureAlgorithm != null) {
            if (signatureAlgorithm.contains("hmac-sha")
                && securityToken.getSecretKey(signatureAlgorithm) != null) {
                return;
            } else if (!signatureAlgorithm.contains("hmac-sha") && securityToken.getX509Certificates() != null) {
                if (securityToken.getSecretKey(signatureAlgorithm) != null) {
                    return;
                } else {
                    // We have certs but no private key set. Use the CallbackHandler
                    Key key =
                        securityProperties.getSignatureCrypto().getPrivateKey(
                            securityToken.getX509Certificates()[0], securityProperties.getCallbackHandler()
                        );
                    securityToken.setSecretKey(signatureAlgorithm, key);
                    return;
                }
            }
        }

        // We have no supplied key. So use the PasswordCallback to get a secret key or password
        String alias = securityProperties.getSignatureUser();
        WSPasswordCallback pwCb = new WSPasswordCallback(alias, WSPasswordCallback.SIGNATURE);
            WSSUtils.doPasswordCallback(securityProperties.getCallbackHandler(), pwCb);

        String password = pwCb.getPassword();
        byte[] secretKey = pwCb.getKey();
        Key key = null;
        X509Certificate[] x509Certificates = null;
        try {
            if (password != null && securityProperties.getSignatureCrypto() != null) {
                key = securityProperties.getSignatureCrypto().getPrivateKey(alias, password);
                CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
                cryptoType.setAlias(alias);
                x509Certificates = securityProperties.getSignatureCrypto().getX509Certificates(cryptoType);
                if (x509Certificates == null || x509Certificates.length == 0) {
                    throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_SIGNATURE, "noUserCertsFound",
                                                  new Object[] {alias});
                }
            } else if (secretKey != null) {
                x509Certificates = null;
                String algoFamily = JCEAlgorithmMapper.getJCEKeyAlgorithmFromURI(signatureAlgorithm);
                key = new SecretKeySpec(secretKey, algoFamily);
            } else {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_SIGNATURE, "noPassword",
                                              new Object[] {alias});
            }
        } catch (WSSecurityException ex) {
            if (signedSAML && securityProperties.getSamlCallbackHandler() != null) {
                // We may get the keys we require from the SAML CallbackHandler...
                return;
            }
            throw ex;
        }

        // Create a new outbound Signature token for the generated key / cert
        final String id = IDGenerator.generateID(null);
        final GenericOutboundSecurityToken binarySecurityToken =
                new GenericOutboundSecurityToken(id, WSSecurityTokenConstants.X509V3Token, key, x509Certificates);

        // binarySecurityToken.setSha1Identifier(reference);
        final SecurityTokenProvider<OutboundSecurityToken> binarySecurityTokenProvider =
                new SecurityTokenProvider<OutboundSecurityToken>() {

            @Override
            public OutboundSecurityToken getSecurityToken() throws WSSecurityException {
                return binarySecurityToken;
            }

            @Override
            public String getId() {
                return id;
            }
        };

        outputProcessorChain.getSecurityContext().registerSecurityTokenProvider(id, binarySecurityTokenProvider);
        outputProcessorChain.getSecurityContext().put(WSSConstants.PROP_USE_THIS_TOKEN_ID_FOR_SIGNATURE, id);
    }

    private void setupEncryptionKey(
        OutputProcessorChainImpl outputProcessorChain,
        WSSSecurityProperties securityProperties
    ) throws XMLSecurityException {
        final String symmetricEncryptionAlgorithm = securityProperties.getEncryptionSymAlgorithm();

        // First check to see if a Symmetric key is available
        GenericOutboundSecurityToken securityToken =
            getOutboundSecurityToken(outputProcessorChain, WSSConstants.PROP_USE_THIS_TOKEN_ID_FOR_ENCRYPTION);
        if (securityToken == null || securityToken.getSecretKey(symmetricEncryptionAlgorithm) == null) {
            //prepare the symmetric session key for all encryption parts
            String keyAlgorithm = JCEAlgorithmMapper.getJCEKeyAlgorithmFromURI(securityProperties.getEncryptionSymAlgorithm());
            KeyGenerator keyGen;
            try {
                keyGen = KeyGenerator.getInstance(keyAlgorithm);
            } catch (NoSuchAlgorithmException e) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, e);
            }
            //the sun JCE provider expects the real key size for 3DES (112 or 168 bit)
            //whereas bouncy castle expects the block size of 128 or 192 bits
            if (keyAlgorithm.contains("AES")) {
                int keyLength = JCEAlgorithmMapper.getKeyLengthFromURI(securityProperties.getEncryptionSymAlgorithm());
                keyGen.init(keyLength);
            }

            final Key symmetricKey = keyGen.generateKey();
            final String symmId = IDGenerator.generateID(null);

            final GenericOutboundSecurityToken symmetricSecurityToken =
                new GenericOutboundSecurityToken(symmId, WSSecurityTokenConstants.EncryptedKeyToken, symmetricKey);
            securityToken = symmetricSecurityToken;
            final SecurityTokenProvider<OutboundSecurityToken> securityTokenProvider =
                new SecurityTokenProvider<OutboundSecurityToken>() {

                @Override
                public OutboundSecurityToken getSecurityToken() throws XMLSecurityException {
                    return symmetricSecurityToken;
                }

                @Override
                public String getId() {
                    return symmId;
                }
            };

            outputProcessorChain.getSecurityContext().registerSecurityTokenProvider(symmId, securityTokenProvider);
            outputProcessorChain.getSecurityContext().put(WSSConstants.PROP_USE_THIS_TOKEN_ID_FOR_ENCRYPTION, symmId);
        }

        if (!securityProperties.isEncryptSymmetricEncryptionKey()) {
            // No EncryptedKey Token required here, so return
            return;
        }

        // Set up a security token with the certs required to encrypt the symmetric key
        X509Certificate[] x509Certificates = null;
        PublicKey publicKey = null;
        if (securityProperties.isUseReqSigCertForEncryption()) {
            X509Certificate x509Certificate = getReqSigCert(outputProcessorChain.getSecurityContext());
            if (x509Certificate == null) {
                publicKey = getReqSigPublicKey(outputProcessorChain.getSecurityContext());
                if (publicKey == null) {
                    throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_ENCRYPTION, "noCert");
                }
            } else {
                x509Certificates = new X509Certificate[1];
                x509Certificates[0] = x509Certificate;
            }
        } else if (securityProperties.getEncryptionUseThisCertificate() != null) {
            x509Certificates = new X509Certificate[1];
            x509Certificates[0] = securityProperties.getEncryptionUseThisCertificate();
        } else {
            CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
            cryptoType.setAlias(securityProperties.getEncryptionUser());
            Crypto crypto = securityProperties.getEncryptionCrypto();
            x509Certificates = crypto.getX509Certificates(cryptoType);
            if (x509Certificates == null || x509Certificates.length == 0) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_ENCRYPTION, "noUserCertsFound",
                                              new Object[] {securityProperties.getEncryptionUser(), "encryption"});
            }
        }

        // Check for Revocation
        if (securityProperties.isEnableRevocation() && x509Certificates != null) {
            Crypto crypto = securityProperties.getEncryptionCrypto();
            crypto.verifyTrust(x509Certificates, true, null);
        }

        // Create a new outbound EncryptedKey token for the cert
        final String id = IDGenerator.generateID(null);
        final GenericOutboundSecurityToken encryptedKeyToken =
            new GenericOutboundSecurityToken(id, WSSecurityTokenConstants.X509V3Token, publicKey, x509Certificates);

        encryptedKeyToken.addWrappedToken(securityToken);
        securityToken.setKeyWrappingToken(encryptedKeyToken);

        // binarySecurityToken.setSha1Identifier(reference);
        final SecurityTokenProvider<OutboundSecurityToken> encryptedKeyTokenProvider =
            new SecurityTokenProvider<OutboundSecurityToken>() {

            @Override
            public OutboundSecurityToken getSecurityToken() throws WSSecurityException {
                return encryptedKeyToken;
            }

            @Override
            public String getId() {
                return id;
            }
        };

        outputProcessorChain.getSecurityContext().registerSecurityTokenProvider(id, encryptedKeyTokenProvider);
        outputProcessorChain.getSecurityContext().put(WSSConstants.PROP_USE_THIS_TOKEN_ID_FOR_ENCRYPTED_KEY, id);
    }

    private void setupKerberosKey(
        OutputProcessorChainImpl outputProcessorChain,
        WSSSecurityProperties securityProperties,
        boolean signature,
        boolean encryption
    ) throws XMLSecurityException {
        GenericOutboundSecurityToken securityToken =
            getOutboundSecurityToken(outputProcessorChain, WSSConstants.PROP_USE_THIS_TOKEN_ID_FOR_KERBEROS);
        String kerberosId = null;
        // First off, see if we have a supplied token
        if (securityToken == null) {
            // If not then generate a new key
            final String id = IDGenerator.generateID(null);
            kerberosId = id;
            final KerberosClientSecurityToken kerberosClientSecurityToken =
                    new KerberosClientSecurityToken(
                        securityProperties.getCallbackHandler(), id
                    );

            final SecurityTokenProvider<OutboundSecurityToken> kerberosSecurityTokenProvider =
                    new SecurityTokenProvider<OutboundSecurityToken>() {

                @Override
                public OutboundSecurityToken getSecurityToken() throws WSSecurityException {
                    return kerberosClientSecurityToken;
                }

                @Override
                public String getId() {
                    return id;
                }
            };

            outputProcessorChain.getSecurityContext().registerSecurityTokenProvider(id, kerberosSecurityTokenProvider);
            outputProcessorChain.getSecurityContext().put(WSSConstants.PROP_USE_THIS_TOKEN_ID_FOR_KERBEROS, id);
        } else {
            kerberosId = securityToken.getId();
        }

        if (signature) {
            outputProcessorChain.getSecurityContext().put(WSSConstants.PROP_USE_THIS_TOKEN_ID_FOR_SIGNATURE, kerberosId);
        }
        if (encryption) {
            outputProcessorChain.getSecurityContext().put(WSSConstants.PROP_USE_THIS_TOKEN_ID_FOR_ENCRYPTION, kerberosId);
        }

    }

    // Return an outbound SecurityToken object for a given id (encryption/signature)
    private GenericOutboundSecurityToken getOutboundSecurityToken(
        OutputProcessorChainImpl outputProcessorChain, String id
    ) throws XMLSecurityException {
        String tokenId =
            outputProcessorChain.getSecurityContext().get(id);
        SecurityTokenProvider<OutboundSecurityToken> signatureTokenProvider = null;
        if (tokenId != null) {
            signatureTokenProvider =
                outputProcessorChain.getSecurityContext().getSecurityTokenProvider(tokenId);
            if (signatureTokenProvider != null) {
                return (GenericOutboundSecurityToken)signatureTokenProvider.getSecurityToken();
            }
        }

        return null;
    }

    private X509Certificate getReqSigCert(SecurityContext securityContext) throws XMLSecurityException {
        List<SecurityEvent> securityEventList = securityContext.getAsList(SecurityEvent.class);
        if (securityEventList != null) {
            for (int i = 0; i < securityEventList.size(); i++) {
                SecurityEvent securityEvent = securityEventList.get(i);
                if (securityEvent instanceof TokenSecurityEvent) {
                    @SuppressWarnings("unchecked")
                    TokenSecurityEvent<? extends SecurityToken> tokenSecurityEvent
                        = (TokenSecurityEvent<? extends SecurityToken>) securityEvent;
                    TokenUsage mainSig = WSSecurityTokenConstants.TOKENUSAGE_MAIN_SIGNATURE;
                    if (!tokenSecurityEvent.getSecurityToken().getTokenUsages().contains(mainSig)) {
                        continue;
                    }
                    X509Certificate[] x509Certificates = tokenSecurityEvent.getSecurityToken().getX509Certificates();
                    if (x509Certificates != null && x509Certificates.length > 0) {
                        return x509Certificates[0];
                    }
                }
            }
        }
        return null;
    }
    
    private PublicKey getReqSigPublicKey(SecurityContext securityContext) throws XMLSecurityException {
        List<SecurityEvent> securityEventList = securityContext.getAsList(SecurityEvent.class);
        if (securityEventList != null) {
            for (int i = 0; i < securityEventList.size(); i++) {
                SecurityEvent securityEvent = securityEventList.get(i);
                if (securityEvent instanceof TokenSecurityEvent) {
                    @SuppressWarnings("unchecked")
                    TokenSecurityEvent<? extends SecurityToken> tokenSecurityEvent
                        = (TokenSecurityEvent<? extends SecurityToken>) securityEvent;
                    TokenUsage mainSig = WSSecurityTokenConstants.TOKENUSAGE_MAIN_SIGNATURE;
                    if (!tokenSecurityEvent.getSecurityToken().getTokenUsages().contains(mainSig)) {
                        continue;
                    }
                    PublicKey publicKey = tokenSecurityEvent.getSecurityToken().getPublicKey();
                    if (publicKey != null) {
                        return publicKey;
                    }
                }
            }
        }
        return null;
    }

    private void setDerivedIdentifier(OutputProcessorChainImpl outputProcessorChain, String id) {
        WSSConstants.DerivedKeyTokenReference derivedKeyTokenReference = securityProperties.getDerivedKeyTokenReference();
            switch (derivedKeyTokenReference) {

            case DirectReference:
                outputProcessorChain.getSecurityContext().put(WSSConstants.PROP_USE_THIS_TOKEN_ID_FOR_DERIVED_KEY, id);
                break;
            case EncryptedKey:
                String symmId = outputProcessorChain.getSecurityContext().get(WSSConstants.PROP_USE_THIS_TOKEN_ID_FOR_ENCRYPTION);
                outputProcessorChain.getSecurityContext().put(WSSConstants.PROP_USE_THIS_TOKEN_ID_FOR_DERIVED_KEY, symmId);
                outputProcessorChain.getSecurityContext().put(WSSConstants.PROP_USE_THIS_TOKEN_ID_FOR_ENCRYPTED_KEY, id);
                break;
            case SecurityContextToken:
                outputProcessorChain.getSecurityContext().put(WSSConstants.PROP_USE_THIS_TOKEN_ID_FOR_SECURITYCONTEXTTOKEN, id);
                break;
            }
    }
    
    private ConfiguredAction configureActions(OutputProcessorChainImpl outputProcessorChain) throws XMLSecurityException {
        ConfiguredAction configuredAction = new ConfiguredAction();
        
        //todo some combinations are not possible atm: eg Action.SIGNATURE and Action.USERNAMETOKEN_SIGNED
        //todo they use the same signature parts

        // Check to see whether we have a derived key signature, but not encryption, using
        // an encrypted key reference (as we only want one encrypted key here...)
        boolean derivedSignatureButNotDerivedEncryption = false;
        if (securityProperties.getDerivedKeyTokenReference() == WSSConstants.DerivedKeyTokenReference.EncryptedKey) {
            for (XMLSecurityConstants.Action action : securityProperties.getActions()) {
                if (WSSConstants.SIGNATURE_WITH_DERIVED_KEY.equals(action)) {
                    derivedSignatureButNotDerivedEncryption = true;
                } else if (WSSConstants.ENCRYPT_WITH_DERIVED_KEY.equals(action)) {
                    derivedSignatureButNotDerivedEncryption = false;
                    break;
                }
            }
        }

        for (XMLSecurityConstants.Action action : securityProperties.getActions()) {
            if (WSSConstants.TIMESTAMP.equals(action)) {
                final TimestampOutputProcessor timestampOutputProcessor = new TimestampOutputProcessor();
                initializeOutputProcessor(outputProcessorChain, timestampOutputProcessor, action);

            } else if (WSSConstants.SIGNATURE.equals(action)) {
                configuredAction.signatureAction = true;
                final BinarySecurityTokenOutputProcessor binarySecurityTokenOutputProcessor =
                    new BinarySecurityTokenOutputProcessor();
                initializeOutputProcessor(outputProcessorChain, binarySecurityTokenOutputProcessor, action);

                final WSSSignatureOutputProcessor signatureOutputProcessor = new WSSSignatureOutputProcessor();
                initializeOutputProcessor(outputProcessorChain, signatureOutputProcessor, action);

            } else if (WSSConstants.ENCRYPT.equals(action)) {
                configuredAction.encryptionAction = true;

                EncryptedKeyOutputProcessor encryptedKeyOutputProcessor = null;
                if (securityProperties.isEncryptSymmetricEncryptionKey()) {
                    final BinarySecurityTokenOutputProcessor binarySecurityTokenOutputProcessor =
                        new BinarySecurityTokenOutputProcessor();
                    initializeOutputProcessor(outputProcessorChain, binarySecurityTokenOutputProcessor, action);

                    encryptedKeyOutputProcessor = new EncryptedKeyOutputProcessor();
                    initializeOutputProcessor(outputProcessorChain, encryptedKeyOutputProcessor, action);
                }

                final EncryptOutputProcessor encryptOutputProcessor = new EncryptOutputProcessor();
                initializeOutputProcessor(outputProcessorChain, encryptOutputProcessor, action);

                if (encryptedKeyOutputProcessor == null) {
                    final ReferenceListOutputProcessor referenceListOutputProcessor = new ReferenceListOutputProcessor();
                    referenceListOutputProcessor.addAfterProcessor(EncryptEndingOutputProcessor.class.getName());
                    initializeOutputProcessor(outputProcessorChain, referenceListOutputProcessor, action);
                }

            } else if (WSSConstants.USERNAMETOKEN.equals(action)) {
                final UsernameTokenOutputProcessor usernameTokenOutputProcessor = new UsernameTokenOutputProcessor();
                initializeOutputProcessor(outputProcessorChain, usernameTokenOutputProcessor, action);

            } else if (WSSConstants.USERNAMETOKEN_SIGNED.equals(action)) {
                final UsernameTokenOutputProcessor usernameTokenOutputProcessor = new UsernameTokenOutputProcessor();
                initializeOutputProcessor(outputProcessorChain, usernameTokenOutputProcessor, action);

                final WSSSignatureOutputProcessor signatureOutputProcessor = new WSSSignatureOutputProcessor();
                initializeOutputProcessor(outputProcessorChain, signatureOutputProcessor, action);

            } else if (WSSConstants.SIGNATURE_CONFIRMATION.equals(action)) {
                final SignatureConfirmationOutputProcessor signatureConfirmationOutputProcessor =
                        new SignatureConfirmationOutputProcessor();
                initializeOutputProcessor(outputProcessorChain, signatureConfirmationOutputProcessor, action);

            } else if (WSSConstants.SIGNATURE_WITH_DERIVED_KEY.equals(action)) {
                if (securityProperties.getDerivedKeyTokenReference() == WSSConstants.DerivedKeyTokenReference.EncryptedKey) {
                    if (derivedSignatureButNotDerivedEncryption) {
                        final EncryptedKeyOutputProcessor encryptedKeyOutputProcessor = new EncryptedKeyOutputProcessor();
                        initializeOutputProcessor(outputProcessorChain, encryptedKeyOutputProcessor, action);
                    }
                    configuredAction.encryptionAction = true;
                    configuredAction.derivedEncryption = true;
                } else if (securityProperties.getDerivedKeyTokenReference() 
                    == WSSConstants.DerivedKeyTokenReference.SecurityContextToken) {
                    final SecurityContextTokenOutputProcessor securityContextTokenOutputProcessor =
                            new SecurityContextTokenOutputProcessor();
                    initializeOutputProcessor(outputProcessorChain, securityContextTokenOutputProcessor, action);
                    configuredAction.signatureAction = true;
                    configuredAction.derivedSignature = true;
                } else {
                    configuredAction.signatureAction = true;
                    configuredAction.derivedSignature = true;
                }

                final DerivedKeyTokenOutputProcessor derivedKeyTokenOutputProcessor = new DerivedKeyTokenOutputProcessor();
                initializeOutputProcessor(outputProcessorChain, derivedKeyTokenOutputProcessor, action);

                final WSSSignatureOutputProcessor signatureOutputProcessor = new WSSSignatureOutputProcessor();
                initializeOutputProcessor(outputProcessorChain, signatureOutputProcessor, action);

            } else if (WSSConstants.ENCRYPT_WITH_DERIVED_KEY.equals(action)) {
                configuredAction.encryptionAction = true;
                configuredAction.derivedEncryption = true;

                EncryptedKeyOutputProcessor encryptedKeyOutputProcessor = null;

                if (securityProperties.getDerivedKeyTokenReference() == WSSConstants.DerivedKeyTokenReference.EncryptedKey) {
                    encryptedKeyOutputProcessor = new EncryptedKeyOutputProcessor();
                    initializeOutputProcessor(outputProcessorChain, encryptedKeyOutputProcessor, action);

                } else if (securityProperties.getDerivedKeyTokenReference() 
                    == WSSConstants.DerivedKeyTokenReference.SecurityContextToken) {
                    final SecurityContextTokenOutputProcessor securityContextTokenOutputProcessor =
                            new SecurityContextTokenOutputProcessor();
                    initializeOutputProcessor(outputProcessorChain, securityContextTokenOutputProcessor, action);
                }
                final DerivedKeyTokenOutputProcessor derivedKeyTokenOutputProcessor = new DerivedKeyTokenOutputProcessor();
                initializeOutputProcessor(outputProcessorChain, derivedKeyTokenOutputProcessor, action);

                final EncryptOutputProcessor encryptOutputProcessor = new EncryptOutputProcessor();
                initializeOutputProcessor(outputProcessorChain, encryptOutputProcessor, action);

                if (encryptedKeyOutputProcessor == null) {
                    final ReferenceListOutputProcessor referenceListOutputProcessor = new ReferenceListOutputProcessor();
                    referenceListOutputProcessor.addAfterProcessor(EncryptEndingOutputProcessor.class.getName());
                    initializeOutputProcessor(outputProcessorChain, referenceListOutputProcessor, action);
                }
            } else if (WSSConstants.SAML_TOKEN_SIGNED.equals(action)) {
                configuredAction.signatureAction = true;
                configuredAction.signedSAML = true;
                final BinarySecurityTokenOutputProcessor binarySecurityTokenOutputProcessor =
                    new BinarySecurityTokenOutputProcessor();
                initializeOutputProcessor(outputProcessorChain, binarySecurityTokenOutputProcessor, action);

                final SAMLTokenOutputProcessor samlTokenOutputProcessor = new SAMLTokenOutputProcessor();
                initializeOutputProcessor(outputProcessorChain, samlTokenOutputProcessor, action);

                final WSSSignatureOutputProcessor signatureOutputProcessor = new WSSSignatureOutputProcessor();
                initializeOutputProcessor(outputProcessorChain, signatureOutputProcessor, action);

            } else if (WSSConstants.SAML_TOKEN_UNSIGNED.equals(action)) {
                final SAMLTokenOutputProcessor samlTokenOutputProcessor = new SAMLTokenOutputProcessor();
                initializeOutputProcessor(outputProcessorChain, samlTokenOutputProcessor, action);
            } else if (WSSConstants.SIGNATURE_WITH_KERBEROS_TOKEN.equals(action)) {
                configuredAction.kerberos = true;
                configuredAction.signatureKerberos = true;
                final BinarySecurityTokenOutputProcessor kerberosTokenOutputProcessor =
                        new BinarySecurityTokenOutputProcessor();
                initializeOutputProcessor(outputProcessorChain, kerberosTokenOutputProcessor, action);

                final WSSSignatureOutputProcessor signatureOutputProcessor = new WSSSignatureOutputProcessor();
                initializeOutputProcessor(outputProcessorChain, signatureOutputProcessor, action);
            } else if (WSSConstants.ENCRYPT_WITH_KERBEROS_TOKEN.equals(action)) {
                configuredAction.kerberos = true;
                configuredAction.encryptionKerberos = true;
                final BinarySecurityTokenOutputProcessor kerberosTokenOutputProcessor =
                        new BinarySecurityTokenOutputProcessor();
                initializeOutputProcessor(outputProcessorChain, kerberosTokenOutputProcessor, action);

                final EncryptOutputProcessor encryptOutputProcessor = new EncryptOutputProcessor();
                initializeOutputProcessor(outputProcessorChain, encryptOutputProcessor, action);
            } else if (WSSConstants.KERBEROS_TOKEN.equals(action)) {
                configuredAction.kerberos = true;
                final BinarySecurityTokenOutputProcessor kerberosTokenOutputProcessor =
                    new BinarySecurityTokenOutputProcessor();
                initializeOutputProcessor(outputProcessorChain, kerberosTokenOutputProcessor, action);
            } else if (WSSConstants.CUSTOM_TOKEN.equals(action)) {
                final CustomTokenOutputProcessor unknownTokenOutputProcessor =
                    new CustomTokenOutputProcessor();
                initializeOutputProcessor(outputProcessorChain, unknownTokenOutputProcessor, action);
            }
        }
        
        return configuredAction;
    }
    
    private static class ConfiguredAction {
        boolean signatureAction = false;
        boolean encryptionAction = false;
        boolean signedSAML = false;
        boolean kerberos = false;
        boolean signatureKerberos = false;
        boolean encryptionKerberos = false;
        boolean derivedSignature = false;
        boolean derivedEncryption = false;
    }
}
