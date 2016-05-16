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
package org.apache.wss4j.stax.securityToken;

import org.apache.xml.security.stax.securityToken.SecurityTokenConstants;

public class WSSecurityTokenConstants extends SecurityTokenConstants {

    public static final TokenUsage TOKENUSAGE_MAIN_SIGNATURE = new TokenUsage("MainSignature");
    public static final TokenUsage TOKENUSAGE_MAIN_ENCRYPTION = new TokenUsage("MainEncryption");
    public static final TokenUsage TOKENUSAGE_SUPPORTING_TOKENS = new TokenUsage("SupportingTokens");
    public static final TokenUsage TOKENUSAGE_SIGNED_SUPPORTING_TOKENS = new TokenUsage("SignedSupportingTokens");
    public static final TokenUsage TOKENUSAGE_ENDORSING_SUPPORTING_TOKENS = 
        new TokenUsage("EndorsingSupportingTokens");
    public static final TokenUsage TOKENUSAGE_SIGNED_ENDORSING_SUPPORTING_TOKENS = 
        new TokenUsage("SignedEndorsingSupportingTokens");
    public static final TokenUsage TOKENUSAGE_SIGNED_ENCRYPTED_SUPPORTING_TOKENS = 
        new TokenUsage("SignedEncryptedSupportingTokens");
    public static final TokenUsage TOKENUSAGE_ENCRYPTED_SUPPORTING_TOKENS = 
        new TokenUsage("EncryptedSupportingTokens");
    public static final TokenUsage TOKENUSAGE_ENDORSING_ENCRYPTED_SUPPORTING_TOKENS = 
        new TokenUsage("EndorsingEncryptedSupportingTokens");
    public static final TokenUsage TOKENUSAGE_SIGNED_ENDORSING_ENCRYPTED_SUPPORTING_TOKENS = 
        new TokenUsage("SignedEndorsingEncryptedSupportingTokens");

    public static final KeyIdentifier KEYIDENTIFIER_SECURITY_TOKEN_DIRECT_REFERENCE = 
        new KeyIdentifier("SecurityTokenDirectReference");
    public static final KeyIdentifier KEYIDENTIFIER_THUMBPRINT_IDENTIFIER = 
        new KeyIdentifier("ThumbprintIdentifier");
    public static final KeyIdentifier KEYIDENTIFIER_ENCRYPTED_KEY_SHA1_IDENTIFIER = 
        new KeyIdentifier("EncryptedKeySha1Identifier");
    public static final KeyIdentifier KEYIDENTIFIER_KERBEROS_SHA1_IDENTIFIER = 
        new KeyIdentifier("KerberosSha1Identifier");
    public static final KeyIdentifier KEYIDENTIFIER_EMBEDDED_KEY_IDENTIFIER_REF = 
        new KeyIdentifier("EmbeddedKeyIdentifierRef");
    public static final KeyIdentifier KEYIDENTIFIER_USERNAME_TOKEN_REFERENCE = 
        new KeyIdentifier("UsernameTokenReference");
    public static final KeyIdentifier KEYIDENTIFIER_EXTERNAL_REFERENCE = 
        new KeyIdentifier("ExternalReference");

    public static final TokenType USERNAME_TOKEN = new TokenType("UsernameToken");
    public static final TokenType SECURITY_CONTEXT_TOKEN = new TokenType("SecurityContextToken");
    public static final TokenType SAML_10_TOKEN = new TokenType("Saml10Token");
    public static final TokenType SAML_11_TOKEN = new TokenType("Saml11Token");
    public static final TokenType SAML_20_TOKEN = new TokenType("Saml20Token");
    public static final TokenType ISSUED_TOKEN = new TokenType("IssuedToken");
    public static final TokenType SECURE_CONVERSATION_TOKEN = new TokenType("SecureConversationToken");
    public static final TokenType HTTPS_TOKEN = new TokenType("HttpsToken");
    public static final TokenType KERBEROS_TOKEN = new TokenType("KerberosToken");
    public static final TokenType SPNEGO_CONTEXT_TOKEN = new TokenType("SpnegoContextToken");
    public static final TokenType REL_TOKEN = new TokenType("RelToken");
   
    // CHECKSTYLE:OFF
    @Deprecated public static final TokenUsage TokenUsage_MainSignature = new TokenUsage("MainSignature");
    @Deprecated public static final TokenUsage TokenUsage_MainEncryption = new TokenUsage("MainEncryption");
    @Deprecated public static final TokenUsage TokenUsage_SupportingTokens = new TokenUsage("SupportingTokens");
    @Deprecated public static final TokenUsage TokenUsage_SignedSupportingTokens = new TokenUsage("SignedSupportingTokens");
    @Deprecated public static final TokenUsage TokenUsage_EndorsingSupportingTokens = new TokenUsage("EndorsingSupportingTokens");
    @Deprecated public static final TokenUsage TokenUsage_SignedEndorsingSupportingTokens = new TokenUsage("SignedEndorsingSupportingTokens");
    @Deprecated public static final TokenUsage TokenUsage_SignedEncryptedSupportingTokens = new TokenUsage("SignedEncryptedSupportingTokens");
    @Deprecated public static final TokenUsage TokenUsage_EncryptedSupportingTokens = new TokenUsage("EncryptedSupportingTokens");
    @Deprecated public static final TokenUsage TokenUsage_EndorsingEncryptedSupportingTokens = new TokenUsage("EndorsingEncryptedSupportingTokens");
    @Deprecated public static final TokenUsage TokenUsage_SignedEndorsingEncryptedSupportingTokens = new TokenUsage("SignedEndorsingEncryptedSupportingTokens");

    @Deprecated public static final KeyIdentifier KeyIdentifier_SecurityTokenDirectReference = new KeyIdentifier("SecurityTokenDirectReference");
    @Deprecated public static final KeyIdentifier KeyIdentifier_ThumbprintIdentifier = new KeyIdentifier("ThumbprintIdentifier");
    @Deprecated public static final KeyIdentifier KeyIdentifier_EncryptedKeySha1Identifier = new KeyIdentifier("EncryptedKeySha1Identifier");
    @Deprecated public static final KeyIdentifier KeyIdentifier_KerberosSha1Identifier = new KeyIdentifier("KerberosSha1Identifier");
    @Deprecated public static final KeyIdentifier KeyIdentifier_EmbeddedKeyIdentifierRef = new KeyIdentifier("EmbeddedKeyIdentifierRef");
    @Deprecated public static final KeyIdentifier KeyIdentifier_UsernameTokenReference = new KeyIdentifier("UsernameTokenReference");
    @Deprecated public static final KeyIdentifier KeyIdentifier_ExternalReference = new KeyIdentifier("ExternalReference");

    @Deprecated public static final TokenType UsernameToken = new TokenType("UsernameToken");
    @Deprecated public static final TokenType SecurityContextToken = new TokenType("SecurityContextToken");
    @Deprecated public static final TokenType Saml10Token = new TokenType("Saml10Token");
    @Deprecated public static final TokenType Saml11Token = new TokenType("Saml11Token");
    @Deprecated public static final TokenType Saml20Token = new TokenType("Saml20Token");
    @Deprecated public static final TokenType IssuedToken = new TokenType("IssuedToken");
    @Deprecated public static final TokenType SecureConversationToken = new TokenType("SecureConversationToken");
    @Deprecated public static final TokenType HttpsToken = new TokenType("HttpsToken");
    @Deprecated public static final TokenType KerberosToken = new TokenType("KerberosToken");
    @Deprecated public static final TokenType SpnegoContextToken = new TokenType("SpnegoContextToken");
    @Deprecated public static final TokenType RelToken = new TokenType("RelToken");
    // CHECKSTYLE:ON
}
