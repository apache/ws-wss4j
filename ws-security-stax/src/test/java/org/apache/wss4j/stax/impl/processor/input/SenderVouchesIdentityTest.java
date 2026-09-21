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
package org.apache.wss4j.stax.impl.processor.input;

import java.security.KeyStore;
import java.security.cert.X509Certificate;

import org.apache.wss4j.stax.impl.securityToken.EncryptedKeySha1SecurityTokenImpl;
import org.apache.wss4j.stax.securityToken.WSSecurityTokenConstants;
import org.apache.xml.security.stax.securityToken.SecurityTokenConstants;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * An unsigned sender-vouches assertion is only as good as the identity of whoever signed the
 * message that carries it. These are the cases SAMLTokenInputHandler#establishesSenderIdentity
 * has to separate: a credential the receiver made a trust decision about, against a bare
 * symmetric key that says nothing about who sent the message.
 */
public class SenderVouchesIdentityTest {

    /**
     * The bypass: an EncryptedKey the sender minted for itself under the receiver's public
     * certificate. The HMAC signature it keys verifies perfectly and identifies nobody.
     */
    @Test
    public void testEncryptedKeyDoesNotVouch() throws Exception {
        assertFalse(SAMLTokenInputHandler.establishesSenderIdentity(
            token(WSSecurityTokenConstants.EncryptedKeyToken)));
    }

    /**
     * The same key reached through a DerivedKeyToken. The derived token is judged on what it was
     * derived from, so this must not become a way round the previous case.
     */
    @Test
    public void testKeyDerivedFromAnEncryptedKeyDoesNotVouch() throws Exception {
        EncryptedKeySha1SecurityTokenImpl derivedKey = token(WSSecurityTokenConstants.DerivedKeyToken);
        derivedKey.setKeyWrappingToken(token(WSSecurityTokenConstants.EncryptedKeyToken));

        assertFalse(SAMLTokenInputHandler.establishesSenderIdentity(derivedKey));
    }

    /**
     * A certificate was checked against the receiver's truststore when the token was verified.
     */
    @Test
    public void testCertificateVouches() throws Exception {
        EncryptedKeySha1SecurityTokenImpl securityToken = token(WSSecurityTokenConstants.X509V3Token);
        securityToken.setX509Certificates(new X509Certificate[] {transmitterCertificate()});

        assertTrue(SAMLTokenInputHandler.establishesSenderIdentity(securityToken));
    }

    /**
     * So was a bare public key - see RsaKeyValueSecurityTokenImpl#verify.
     */
    @Test
    public void testPublicKeyVouches() throws Exception {
        EncryptedKeySha1SecurityTokenImpl securityToken = token(WSSecurityTokenConstants.KeyValueToken);
        securityToken.setPublicKey(transmitterCertificate().getPublicKey());

        assertTrue(SAMLTokenInputHandler.establishesSenderIdentity(securityToken));
    }

    /**
     * A UsernameToken derived key carries no credential for a trust decision, but deriving it
     * required the password, so the sender is authenticated all the same. This is the streaming
     * counterpart of the DOM engine's UT_SIGN case.
     */
    @Test
    public void testUsernameTokenVouches() throws Exception {
        assertTrue(SAMLTokenInputHandler.establishesSenderIdentity(
            token(WSSecurityTokenConstants.USERNAME_TOKEN)));
    }

    /**
     * A Kerberos session key came out of a ticket the KDC issued to a named client.
     */
    @Test
    public void testKerberosTokenVouches() throws Exception {
        assertTrue(SAMLTokenInputHandler.establishesSenderIdentity(
            token(WSSecurityTokenConstants.KERBEROS_TOKEN)));
    }

    /**
     * A token carrying only a symmetric key of some other provenance - a SecurityContextToken,
     * say - is no better placed to vouch than an EncryptedKey is.
     */
    @Test
    public void testOtherSymmetricTokenDoesNotVouch() throws Exception {
        assertFalse(SAMLTokenInputHandler.establishesSenderIdentity(
            token(WSSecurityTokenConstants.SECURITY_CONTEXT_TOKEN)));
    }

    /**
     * A token of the given type carrying nothing else. EncryptedKeySha1SecurityTokenImpl is used
     * only because it is a concrete inbound token whose credentials can be set from a test; what
     * is under test is the rule, not the class.
     */
    private EncryptedKeySha1SecurityTokenImpl token(SecurityTokenConstants.TokenType tokenType) {
        return new EncryptedKeySha1SecurityTokenImpl(null, null, "sha1-identifier", "token-id") {
            @Override
            public SecurityTokenConstants.TokenType getTokenType() {
                return tokenType;
            }
        };
    }

    private X509Certificate transmitterCertificate() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(this.getClass().getClassLoader().getResourceAsStream("transmitter.jks"),
                      "default".toCharArray());
        X509Certificate certificate = (X509Certificate)keyStore.getCertificate("transmitter");
        assertNotNull(certificate, "precondition: the test keystore holds the transmitter certificate");
        return certificate;
    }
}
