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
import org.junit.Assert;
import org.junit.Test;

/**
 * Some tests for the ConfigurationConverter utility
 */
public class ConfigurationConverterTest extends AbstractTestBase {

    @Test
    public void testUsernameTokenConfiguration() throws Exception {
        Map<String, Object> config = new HashMap<String, Object>();
        config.put(ConfigurationConstants.ACTION, ConfigurationConstants.USERNAME_TOKEN);
        config.put(ConfigurationConstants.USER, "testuser");
        config.put(ConfigurationConstants.PW_CALLBACK_CLASS, "org.apache.wss4j.stax.test.CallbackHandlerImpl");
        config.put(ConfigurationConstants.PASSWORD_TYPE, "PasswordText");
        config.put(ConfigurationConstants.ADD_USERNAMETOKEN_NONCE, "true");
        config.put(ConfigurationConstants.ADD_USERNAMETOKEN_CREATED, "false");

        WSSSecurityProperties properties = ConfigurationConverter.convert(config);
        Assert.assertEquals(properties.getTokenUser(), "testuser");
        Assert.assertEquals(properties.getActions().size(), 1);
        Assert.assertEquals(properties.getActions().get(0), WSSConstants.USERNAMETOKEN);
        Assert.assertTrue(properties.getCallbackHandler() instanceof CallbackHandlerImpl);
        Assert.assertEquals(properties.getUsernameTokenPasswordType(),
                            UsernameTokenPasswordType.PASSWORD_TEXT);
        Assert.assertTrue(properties.isAddUsernameTokenNonce());
        Assert.assertFalse(properties.isAddUsernameTokenCreated());

        WSSec.validateAndApplyDefaultsToOutboundSecurityProperties(properties);
    }

    @Test
    public void testOutboundSignatureConfiguration() throws Exception {
        Map<String, Object> config = new HashMap<String, Object>();
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

        Assert.assertEquals(properties.getSignatureUser(), "transmitter");
        Assert.assertEquals(properties.getActions().size(), 1);
        Assert.assertEquals(properties.getActions().get(0), WSSConstants.SIGNATURE);
        Assert.assertTrue(properties.getCallbackHandler() instanceof CallbackHandlerImpl);
        Assert.assertEquals(properties.getSignatureAlgorithm(), sigAlgo);
        Assert.assertEquals(properties.getSignatureKeyIdentifier(),
                            WSSecurityTokenConstants.KeyIdentifier_ThumbprintIdentifier);
        Assert.assertFalse(properties.isAddExcC14NInclusivePrefixes());
        Assert.assertNotNull(properties.getSignatureCrypto());
        Assert.assertTrue(properties.getSignatureSecureParts() != null);
        Assert.assertEquals(properties.getSignatureSecureParts().size(), 1);
        Assert.assertEquals(properties.getSignatureSecureParts().get(0).getName().getLocalPart(),
                            "Body");
        Assert.assertEquals(properties.getSignatureSecureParts().get(0).getName().getNamespaceURI(),
                            "http://schemas.xmlsoap.org/soap/envelope/");

        WSSec.validateAndApplyDefaultsToOutboundSecurityProperties(properties);
    }

    @Test
    public void testInboundSignatureConfiguration() throws Exception {
        Map<String, Object> config = new HashMap<String, Object>();
        config.put(ConfigurationConstants.ACTION, ConfigurationConstants.SIGNATURE);
        config.put(ConfigurationConstants.PW_CALLBACK_REF, new CallbackHandlerImpl());
        config.put(ConfigurationConstants.ADD_INCLUSIVE_PREFIXES, "false");
        config.put(ConfigurationConstants.SIG_VER_PROP_FILE, "transmitter-crypto.properties");
        config.put(ConfigurationConstants.IS_BSP_COMPLIANT, "false");
        config.put(ConfigurationConstants.ENABLE_REVOCATION, "true");

        WSSSecurityProperties properties = ConfigurationConverter.convert(config);

        Assert.assertEquals(properties.getActions().size(), 1);
        Assert.assertEquals(properties.getActions().get(0), WSSConstants.SIGNATURE);
        Assert.assertTrue(properties.getCallbackHandler() instanceof CallbackHandlerImpl);
        Assert.assertTrue(properties.isDisableBSPEnforcement());
        Assert.assertTrue(properties.isEnableRevocation());
        Assert.assertNotNull(properties.getSignatureVerificationCrypto());

        WSSec.validateAndApplyDefaultsToInboundSecurityProperties(properties);
    }

    @Test
    public void testOutboundEncryptionConfiguration() throws Exception {
        Map<String, Object> config = new HashMap<String, Object>();
        config.put(ConfigurationConstants.ACTION, ConfigurationConstants.ENCRYPT);
        config.put(ConfigurationConstants.USER, "transmitter");
        config.put(ConfigurationConstants.PW_CALLBACK_REF, new CallbackHandlerImpl());
        config.put(ConfigurationConstants.ENC_KEY_TRANSPORT, WSSConstants.NS_XENC_RSA15);
        config.put(ConfigurationConstants.ENC_KEY_ID, "EncryptedKeySHA1");
        config.put(ConfigurationConstants.ENC_PROP_FILE, "receiver-crypto.properties");
        config.put(ConfigurationConstants.ENCRYPTION_PARTS,
                   "{}{http://schemas.xmlsoap.org/soap/envelope/}Body;");

        WSSSecurityProperties properties = ConfigurationConverter.convert(config);

        Assert.assertEquals(properties.getEncryptionUser(), "transmitter");
        Assert.assertEquals(properties.getActions().size(), 1);
        Assert.assertEquals(properties.getActions().get(0), WSSConstants.ENCRYPT);
        Assert.assertTrue(properties.getCallbackHandler() instanceof CallbackHandlerImpl);
        Assert.assertEquals(properties.getEncryptionKeyTransportAlgorithm(),
                            WSSConstants.NS_XENC_RSA15);
        Assert.assertEquals(properties.getEncryptionKeyIdentifier(),
                            WSSecurityTokenConstants.KeyIdentifier_EncryptedKeySha1Identifier);
        Assert.assertNotNull(properties.getEncryptionCrypto());
        Assert.assertTrue(properties.getEncryptionSecureParts() != null);
        Assert.assertEquals(properties.getEncryptionSecureParts().size(), 1);
        Assert.assertEquals(properties.getEncryptionSecureParts().get(0).getName().getLocalPart(),
                            "Body");
        Assert.assertEquals(properties.getEncryptionSecureParts().get(0).getName().getNamespaceURI(),
                            "http://schemas.xmlsoap.org/soap/envelope/");

        WSSec.validateAndApplyDefaultsToOutboundSecurityProperties(properties);
    }

    @Test
    public void testInboundEncryptionConfiguration() throws Exception {
        Map<String, Object> config = new HashMap<String, Object>();
        config.put(ConfigurationConstants.ACTION, ConfigurationConstants.ENCRYPT);
        config.put(ConfigurationConstants.PW_CALLBACK_REF, new CallbackHandlerImpl());
        config.put(ConfigurationConstants.DEC_PROP_FILE, "receiver-crypto.properties");
        config.put(ConfigurationConstants.ALLOW_RSA15_KEY_TRANSPORT_ALGORITHM, "true");

        WSSSecurityProperties properties = ConfigurationConverter.convert(config);

        Assert.assertEquals(properties.getActions().size(), 1);
        Assert.assertEquals(properties.getActions().get(0), WSSConstants.ENCRYPT);
        Assert.assertTrue(properties.getCallbackHandler() instanceof CallbackHandlerImpl);
        Assert.assertNotNull(properties.getDecryptionCrypto());

        WSSec.validateAndApplyDefaultsToInboundSecurityProperties(properties);
    }

    @Test
    public void testSAMLConfiguration() throws Exception {
        Map<String, Object> config = new HashMap<String, Object>();
        config.put(ConfigurationConstants.ACTION, ConfigurationConstants.SAML_TOKEN_UNSIGNED);
        config.put(ConfigurationConstants.SAML_CALLBACK_REF, new SAMLCallbackHandlerImpl());

        WSSSecurityProperties properties = ConfigurationConverter.convert(config);
        Assert.assertEquals(properties.getActions().size(), 1);
        Assert.assertEquals(properties.getActions().get(0), WSSConstants.SAML_TOKEN_UNSIGNED);
        Assert.assertTrue(properties.getSamlCallbackHandler() instanceof SAMLCallbackHandlerImpl);

        WSSec.validateAndApplyDefaultsToOutboundSecurityProperties(properties);
    }

    @Test
    public void testTimestampConfiguration() throws Exception {
        // Outbound
        Map<String, Object> config = new HashMap<String, Object>();
        config.put(ConfigurationConstants.ACTION, ConfigurationConstants.TIMESTAMP);
        config.put(ConfigurationConstants.TTL_TIMESTAMP, "180");

        WSSSecurityProperties properties = ConfigurationConverter.convert(config);
        Assert.assertEquals(properties.getActions().size(), 1);
        Assert.assertEquals(properties.getActions().get(0), WSSConstants.TIMESTAMP);
        Assert.assertEquals(properties.getTimestampTTL(), Integer.valueOf(180));

        WSSec.validateAndApplyDefaultsToOutboundSecurityProperties(properties);

        // Inbound
        config.put(ConfigurationConstants.TTL_FUTURE_TIMESTAMP, "120");
        config.put(ConfigurationConstants.TIMESTAMP_STRICT, "false");

        properties = ConfigurationConverter.convert(config);
        Assert.assertEquals(properties.getTimeStampFutureTTL(), Integer.valueOf(120));
        Assert.assertFalse(properties.isStrictTimestampCheck());

        WSSec.validateAndApplyDefaultsToInboundSecurityProperties(properties);
    }

}
