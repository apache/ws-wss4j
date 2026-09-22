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

package org.apache.wss4j.common.crypto;

import java.security.cert.X509Certificate;

/**
 * Decodes the X.509 key identifier extensions.
 *
 * @deprecated the decoding no longer uses Bouncy Castle, so this class was renamed to
 *             {@link X509KeyIdentifierUtil}. This name is retained for callers compiled against
 *             4.0.1 and earlier, and delegates to the new class. Use
 *             {@link X509KeyIdentifierUtil} instead.
 */
@Deprecated(since = "4.0.2", forRemoval = true)
public final class BouncyCastleUtils {

    private BouncyCastleUtils() {
        // complete
    }

    /**
     * Read the keyIdentifier of the AuthorityKeyIdentifier extension (2.5.29.35) of the
     * given certificate.
     *
     * @param cert the certificate to read the AuthorityKeyIdentifier from.
     * @return an empty array if the certificate has no AuthorityKeyIdentifier extension, null if
     *         the extension is present but carries no keyIdentifier, otherwise the keyIdentifier.
     * @throws IllegalArgumentException if the extension is present but is not valid DER.
     * @deprecated use {@link X509KeyIdentifierUtil#getAuthorityKeyIdentifierBytes(X509Certificate)}
     */
    @Deprecated(since = "4.0.2", forRemoval = true)
    public static byte[] getAuthorityKeyIdentifierBytes(X509Certificate cert) {
        return X509KeyIdentifierUtil.getAuthorityKeyIdentifierBytes(cert);
    }

    /**
     * Read the SubjectKeyIdentifier extension (2.5.29.14) of the given certificate.
     *
     * @param cert the certificate to read the SubjectKeyIdentifier from.
     * @return an empty array if the certificate has no SubjectKeyIdentifier extension, otherwise
     *         the key identifier.
     * @throws IllegalArgumentException if the extension is present but is not valid DER.
     * @deprecated use {@link X509KeyIdentifierUtil#getSubjectKeyIdentifierBytes(X509Certificate)}
     */
    @Deprecated(since = "4.0.2", forRemoval = true)
    public static byte[] getSubjectKeyIdentifierBytes(X509Certificate cert) {
        return X509KeyIdentifierUtil.getSubjectKeyIdentifierBytes(cert);
    }

}
