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

package org.apache.ws.security.components.crypto;

import java.security.PublicKey;
import org.apache.ws.security.WSSecurityException;

/**
 * Represents the X.509 SubjectPublicKeyInfo for a public key, as specified
 * in RFC3280/5280:
 * <pre>
 * SubjectPublicKeyInfo  ::=  SEQUENCE  {
 *       algorithm            AlgorithmIdentifier,
 *       subjectPublicKey     BIT STRING  }
 *
 * AlgorithmIdentifier  ::=  SEQUENCE  {
 *       algorithm               OBJECT IDENTIFIER,
 *       parameters              ANY DEFINED BY algorithm OPTIONAL  }
 * </pre>
 */
public class X509SubjectPublicKeyInfo extends DERDecoder {

    /**
     * Construct a SubjectPublicKeyInfo for the given public key.
     *
     * @param key the public key.
     * @throws WSSecurityException if the public key encoding format is 
     *                             not X.509 or the encoding is null.
     */
    public X509SubjectPublicKeyInfo(PublicKey key) throws WSSecurityException {
        super(key.getEncoded());
        if (!("X.509".equalsIgnoreCase(key.getFormat()) 
                || "X509".equalsIgnoreCase(key.getFormat()))) {
            throw new WSSecurityException(
                WSSecurityException.UNSUPPORTED_SECURITY_TOKEN,
                "noSKIHandling",
                new Object[] { "Support for X.509-encoded public keys only" }
            );
        }
    }

    /**
     * Construct a SubjectPublicKeyInfo for the given X.509-encoded public key.
     *
     * @param x509EncodedPublicKey the public key, in X.509 DER-encoding.
     * @throws WSSecurityException if the encoded public key is null.
     */
    public X509SubjectPublicKeyInfo(byte[] x509EncodedPublicKey) throws WSSecurityException {
        super(x509EncodedPublicKey);
    }

    /**
     * Get the subjectPublicKey element of the SubjectPublicKeyInfo.
     *
     * @return the X.509-encoded subjectPublicKey bit string.
     * @throws WSSecurityException the DER-encoding is invalid.
     */
    public byte[] getSubjectPublicKey() throws WSSecurityException {
        reset();
        expect(TYPE_SEQUENCE);    // SubjectPublicKeyInfo SEQUENCE
        getLength();
        // Could enforce the max length of this sequence, but not actually
        // necessary for our purposes, so be forgiving and simply ignore.
        expect(TYPE_SEQUENCE);    // algorithm AlgorithmIdentifier SEQUENCE
        int algIDlen = getLength();
        if (algIDlen < 0) {
            // Unsupported indefinite-length
            throw new WSSecurityException(
                    WSSecurityException.UNSUPPORTED_SECURITY_TOKEN,
                    "noSKIHandling",
                    new Object[] { "Unsupported X.509 public key format" }
            );
        }
        skip(algIDlen);           // AlgorithmIdentifier contents
        expect(TYPE_BIT_STRING);  // subjectPublicKey BIT STRING
        int keyLen = getLength()-1;
        if (keyLen < 0) {
            // Invalid BIT STRING length
            throw new WSSecurityException(
                    WSSecurityException.UNSUPPORTED_SECURITY_TOKEN,
                    "noSKIHandling",
                    new Object[] { "Invalid X.509 public key format" }
            );
        }
        skip(1);   // number unused bits
        // DER-encoding guarantees unused bits should be 0

        return getBytes(keyLen);
    }
}
