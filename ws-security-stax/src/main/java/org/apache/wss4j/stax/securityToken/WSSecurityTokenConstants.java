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
}
