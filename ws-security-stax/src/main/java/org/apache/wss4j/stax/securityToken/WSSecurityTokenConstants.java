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

    public static final TokenUsage TokenUsage_MainSignature = new TokenUsage("MainSignature");
    public static final TokenUsage TokenUsage_MainEncryption = new TokenUsage("MainEncryption");
    public static final TokenUsage TokenUsage_SupportingTokens = new TokenUsage("SupportingTokens");
    public static final TokenUsage TokenUsage_SignedSupportingTokens = new TokenUsage("SignedSupportingTokens");
    public static final TokenUsage TokenUsage_EndorsingSupportingTokens = new TokenUsage("EndorsingSupportingTokens");
    public static final TokenUsage TokenUsage_SignedEndorsingSupportingTokens = new TokenUsage("SignedEndorsingSupportingTokens");
    public static final TokenUsage TokenUsage_SignedEncryptedSupportingTokens = new TokenUsage("SignedEncryptedSupportingTokens");
    public static final TokenUsage TokenUsage_EncryptedSupportingTokens = new TokenUsage("EncryptedSupportingTokens");
    public static final TokenUsage TokenUsage_EndorsingEncryptedSupportingTokens = new TokenUsage("EndorsingEncryptedSupportingTokens");
    public static final TokenUsage TokenUsage_SignedEndorsingEncryptedSupportingTokens = new TokenUsage("SignedEndorsingEncryptedSupportingTokens");

    public static final KeyIdentifier KeyIdentifier_SecurityTokenDirectReference = new KeyIdentifier("SecurityTokenDirectReference");
    public static final KeyIdentifier KeyIdentifier_ThumbprintIdentifier = new KeyIdentifier("ThumbprintIdentifier");
    public static final KeyIdentifier KeyIdentifier_EncryptedKeySha1Identifier = new KeyIdentifier("EncryptedKeySha1Identifier");
    public static final KeyIdentifier KeyIdentifier_KerberosSha1Identifier = new KeyIdentifier("KerberosSha1Identifier");
    public static final KeyIdentifier KeyIdentifier_EmbeddedKeyIdentifierRef = new KeyIdentifier("EmbeddedKeyIdentifierRef");
    public static final KeyIdentifier KeyIdentifier_UsernameTokenReference = new KeyIdentifier("UsernameTokenReference");
    public static final KeyIdentifier KeyIdentifier_ExternalReference = new KeyIdentifier("ExternalReference");

    public static final TokenType UsernameToken = new TokenType("UsernameToken");
    public static final TokenType SecurityContextToken = new TokenType("SecurityContextToken");
    public static final TokenType Saml10Token = new TokenType("Saml10Token");
    public static final TokenType Saml11Token = new TokenType("Saml11Token");
    public static final TokenType Saml20Token = new TokenType("Saml20Token");
    public static final TokenType IssuedToken = new TokenType("IssuedToken");
    public static final TokenType SecureConversationToken = new TokenType("SecureConversationToken");
    public static final TokenType HttpsToken = new TokenType("HttpsToken");
    public static final TokenType KerberosToken = new TokenType("KerberosToken");
    public static final TokenType SpnegoContextToken = new TokenType("SpnegoContextToken");
    public static final TokenType RelToken = new TokenType("RelToken");
    public static final TokenType DerivedKeyToken = new TokenType("DerivedKeyToken");
}
