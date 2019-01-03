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
package org.apache.wss4j.stax.test;

import java.util.HashMap;
import java.util.Map;

import org.apache.wss4j.common.ConfigurationConstants;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.ext.WSSConstants.UsernameTokenPasswordType;
import org.apache.wss4j.stax.ext.WSSSecurityProperties;
import org.apache.wss4j.stax.securityToken.WSSecurityTokenConstants;
import org.apache.wss4j.stax.setup.ConfigurationConverter;
import org.apache.wss4j.stax.setup.WSSec;
import org.apache.wss4j.stax.test.saml.SAMLCallbackHandlerImpl;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * Some tests for the ConfigurationConverter utility
 */
public class ConfigurationConverterTest extends AbstractTestBase {

    @Test
    public void testUsernameTokenConfiguration() throws Exception {
        Map<String, Object> config = new HashMap<>();
        config.put(ConfigurationConstants.ACTION, ConfigurationConstants.USERNAME_TOKEN);
        config.put(ConfigurationConstants.USER, "testuser");
        config.put(ConfigurationConstants.PW_CALLBACK_CLASS, "org.apache.wss4j.stax.test.CallbackHandlerImpl");
        config.put(ConfigurationConstants.PASSWORD_TYPE, "PasswordText");
        config.put(ConfigurationConstants.ADD_USERNAMETOKEN_NONCE, "true");
        config.put(ConfigurationConstants.ADD_USERNAMETOKEN_CREATED, "false");

        WSSSecurityProperties properties = ConfigurationConverter.convert(config);
        assertEquals(properties.getTokenUser(), "testuser");
        assertEquals(properties.getActions().size(), 1);
        assertEquals(properties.getActions().get(0), WSSConstants.USERNAMETOKEN);
        assertTrue(properties.getCallbackHandler() instanceof CallbackHandlerImpl);
        assertEquals(properties.getUsernameTokenPasswordType(),
                            UsernameTokenPasswordType.PASSWORD_TEXT);
        assertTrue(properties.isAddUsernameTokenNonce());
        assertFalse(properties.isAddUsernameTokenCreated());

        WSSec.validateAndApplyDefaultsToOutboundSecurityProperties(properties);
    }

    @Test
    public void testOutboundSignatureConfiguration() throws Exception {
        Map<String, Object> config = new HashMap<>();
        config.put(ConfigurationConstants.ACTION, ConfigurationConstants.SIGNATURE);
        config.put(ConfigurationConstants.USER, "transmitter");
        config.put(ConfigurationConstants.PW_CALLBACK_REF, new CallbackHandlerImpl());
        String sigAlgo = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
        config.put(ConfigurationConstants.SIG_ALGO, sigAlgo);
        config.put(ConfigurationConstants.SIG_KEY_ID, "Thumbprint");
        config.put(ConfigurationConstants.ADD_INCLUSIVE_PREFIXES, "false");
        config.put(ConfigurationConstants.SIG_PROP_FILE, "transmitter-crypto.properties");
        config.put(ConfigurationConstants.SIGNATURE_PARTS,
                   "{}{http://schemas.xmlsoap.org/soap/envelope/}Body;");

        WSSSecurityProperties properties = ConfigurationConverter.convert(config);

        assertEquals(properties.getSignatureUser(), "transmitter");
        assertEquals(properties.getActions().size(), 1);
        assertEquals(properties.getActions().get(0), WSSConstants.SIGNATURE);
        assertTrue(properties.getCallbackHandler() instanceof CallbackHandlerImpl);
        assertEquals(properties.getSignatureAlgorithm(), sigAlgo);
        assertEquals(properties.getSignatureKeyIdentifiers().size(), 1);
        assertEquals(properties.getSignatureKeyIdentifiers().get(0),
                            WSSecurityTokenConstants.KEYIDENTIFIER_THUMBPRINT_IDENTIFIER);
        assertFalse(properties.isAddExcC14NInclusivePrefixes());
        assertNotNull(properties.getSignatureCrypto());
        assertNotNull(properties.getSignatureSecureParts());
        assertEquals(properties.getSignatureSecureParts().size(), 1);
        assertEquals(properties.getSignatureSecureParts().get(0).getName().getLocalPart(),
                            "Body");
        assertEquals(properties.getSignatureSecureParts().get(0).getName().getNamespaceURI(),
                            "http://schemas.xmlsoap.org/soap/envelope/");

        WSSec.validateAndApplyDefaultsToOutboundSecurityProperties(properties);
    }

    @Test
    public void testInboundSignatureConfiguration() throws Exception {
        Map<String, Object> config = new HashMap<>();
        config.put(ConfigurationConstants.ACTION, ConfigurationConstants.SIGNATURE);
        config.put(ConfigurationConstants.PW_CALLBACK_REF, new CallbackHandlerImpl());
        config.put(ConfigurationConstants.ADD_INCLUSIVE_PREFIXES, "false");
        config.put(ConfigurationConstants.SIG_VER_PROP_FILE, "transmitter-crypto.properties");
        config.put(ConfigurationConstants.IS_BSP_COMPLIANT, "false");
        config.put(ConfigurationConstants.ENABLE_REVOCATION, "true");

        WSSSecurityProperties properties = ConfigurationConverter.convert(config);

        assertEquals(properties.getActions().size(), 1);
        assertEquals(properties.getActions().get(0), WSSConstants.SIGNATURE);
        assertTrue(properties.getCallbackHandler() instanceof CallbackHandlerImpl);
        assertTrue(properties.isDisableBSPEnforcement());
        assertTrue(properties.isEnableRevocation());
        assertNotNull(properties.getSignatureVerificationCrypto());

        WSSec.validateAndApplyDefaultsToInboundSecurityProperties(properties);
    }

    @Test
    public void testOutboundEncryptionConfiguration() throws Exception {
        Map<String, Object> config = new HashMap<>();
        config.put(ConfigurationConstants.ACTION, ConfigurationConstants.ENCRYPT);
        config.put(ConfigurationConstants.USER, "transmitter");
        config.put(ConfigurationConstants.PW_CALLBACK_REF, new CallbackHandlerImpl());
        config.put(ConfigurationConstants.ENC_KEY_TRANSPORT, WSSConstants.NS_XENC_RSA15);
        config.put(ConfigurationConstants.ENC_KEY_ID, "EncryptedKeySHA1");
        config.put(ConfigurationConstants.ENC_PROP_FILE, "receiver-crypto.properties");
        config.put(ConfigurationConstants.ENCRYPTION_PARTS,
                   "{}{http://schemas.xmlsoap.org/soap/envelope/}Body;");

        WSSSecurityProperties properties = ConfigurationConverter.convert(config);

        assertEquals(properties.getEncryptionUser(), "transmitter");
        assertEquals(properties.getActions().size(), 1);
        assertEquals(properties.getActions().get(0), WSSConstants.ENCRYPT);
        assertTrue(properties.getCallbackHandler() instanceof CallbackHandlerImpl);
        assertEquals(properties.getEncryptionKeyTransportAlgorithm(),
                            WSSConstants.NS_XENC_RSA15);
        assertEquals(properties.getEncryptionKeyIdentifier(),
                            WSSecurityTokenConstants.KEYIDENTIFIER_ENCRYPTED_KEY_SHA1_IDENTIFIER);
        assertNotNull(properties.getEncryptionCrypto());
        assertNotNull(properties.getEncryptionSecureParts());
        assertEquals(properties.getEncryptionSecureParts().size(), 1);
        assertEquals(properties.getEncryptionSecureParts().get(0).getName().getLocalPart(),
                            "Body");
        assertEquals(properties.getEncryptionSecureParts().get(0).getName().getNamespaceURI(),
                            "http://schemas.xmlsoap.org/soap/envelope/");

        WSSec.validateAndApplyDefaultsToOutboundSecurityProperties(properties);
    }

    @Test
    public void testInboundEncryptionConfiguration() throws Exception {
        Map<String, Object> config = new HashMap<>();
        config.put(ConfigurationConstants.ACTION, ConfigurationConstants.ENCRYPT);
        config.put(ConfigurationConstants.PW_CALLBACK_REF, new CallbackHandlerImpl());
        config.put(ConfigurationConstants.DEC_PROP_FILE, "receiver-crypto.properties");
        config.put(ConfigurationConstants.ALLOW_RSA15_KEY_TRANSPORT_ALGORITHM, "true");

        WSSSecurityProperties properties = ConfigurationConverter.convert(config);

        assertEquals(properties.getActions().size(), 1);
        assertEquals(properties.getActions().get(0), WSSConstants.ENCRYPT);
        assertTrue(properties.getCallbackHandler() instanceof CallbackHandlerImpl);
        assertNotNull(properties.getDecryptionCrypto());

        WSSec.validateAndApplyDefaultsToInboundSecurityProperties(properties);
    }

    @Test
    public void testSAMLConfiguration() throws Exception {
        Map<String, Object> config = new HashMap<>();
        config.put(ConfigurationConstants.ACTION, ConfigurationConstants.SAML_TOKEN_UNSIGNED);
        config.put(ConfigurationConstants.SAML_CALLBACK_REF, new SAMLCallbackHandlerImpl());

        WSSSecurityProperties properties = ConfigurationConverter.convert(config);
        assertEquals(properties.getActions().size(), 1);
        assertEquals(properties.getActions().get(0), WSSConstants.SAML_TOKEN_UNSIGNED);
        assertTrue(properties.getSamlCallbackHandler() instanceof SAMLCallbackHandlerImpl);

        WSSec.validateAndApplyDefaultsToOutboundSecurityProperties(properties);
    }

    @Test
    public void testTimestampConfiguration() throws Exception {
        // Outbound
        Map<String, Object> config = new HashMap<>();
        config.put(ConfigurationConstants.ACTION, ConfigurationConstants.TIMESTAMP);
        config.put(ConfigurationConstants.TTL_TIMESTAMP, "180");

        WSSSecurityProperties properties = ConfigurationConverter.convert(config);
        assertEquals(properties.getActions().size(), 1);
        assertEquals(properties.getActions().get(0), WSSConstants.TIMESTAMP);
        assertEquals(properties.getTimestampTTL(), Integer.valueOf(180));

        WSSec.validateAndApplyDefaultsToOutboundSecurityProperties(properties);

        // Inbound
        config.put(ConfigurationConstants.TTL_FUTURE_TIMESTAMP, "120");
        config.put(ConfigurationConstants.TIMESTAMP_STRICT, "false");

        properties = ConfigurationConverter.convert(config);
        assertEquals(properties.getTimeStampFutureTTL(), Integer.valueOf(120));
        assertFalse(properties.isStrictTimestampCheck());

        WSSec.validateAndApplyDefaultsToInboundSecurityProperties(properties);
    }

}