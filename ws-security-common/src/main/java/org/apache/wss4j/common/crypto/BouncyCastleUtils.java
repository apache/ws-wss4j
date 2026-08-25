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

import org.apache.wss4j.common.ext.WSSecurityException;

/**
 * Parses X.509 key identifier extensions. The historical class name is retained for binary
 * compatibility, but the implementation is provider-neutral.
 */
public final class BouncyCastleUtils {

    private static final int TYPE_CONTEXT_SPECIFIC_0 = 0x80;

    private BouncyCastleUtils() {
        // complete
    }

    @SuppressWarnings("PMD.ReturnEmptyCollectionRatherThanNull")
    public static byte[] getAuthorityKeyIdentifierBytes(X509Certificate cert) {
        byte[] extensionValue = cert.getExtensionValue("2.5.29.35"); //NOPMD
        if (extensionValue != null) {
            try {
                DERDecoder extension = unwrapExtensionValue(extensionValue);
                extension.expect(DERDecoder.TYPE_SEQUENCE);
                DERDecoder authorityKeyIdentifier =
                    new DERDecoder(extension.getBytes(extension.getLength()));
                if (!authorityKeyIdentifier.hasRemaining()
                    || !authorityKeyIdentifier.test((byte)TYPE_CONTEXT_SPECIFIC_0)) {
                    return null;
                }
                authorityKeyIdentifier.expect(TYPE_CONTEXT_SPECIFIC_0);
                return authorityKeyIdentifier.getBytes(authorityKeyIdentifier.getLength());
            } catch (WSSecurityException ex) {
                throw new IllegalArgumentException("Invalid AuthorityKeyIdentifier extension", ex);
            }
        }
        return new byte[0];
    }

    public static byte[] getSubjectKeyIdentifierBytes(X509Certificate cert) {
        byte[] extensionValue = cert.getExtensionValue("2.5.29.14"); //NOPMD
        if (extensionValue != null) {
            try {
                DERDecoder subjectKeyIdentifier = unwrapExtensionValue(extensionValue);
                subjectKeyIdentifier.expect(DERDecoder.TYPE_OCTET_STRING);
                return subjectKeyIdentifier.getBytes(subjectKeyIdentifier.getLength());
            } catch (WSSecurityException ex) {
                throw new IllegalArgumentException("Invalid SubjectKeyIdentifier extension", ex);
            }
        }
        return new byte[0];
    }

    private static DERDecoder unwrapExtensionValue(byte[] extensionValue) throws WSSecurityException {
        DERDecoder extension = new DERDecoder(extensionValue);
        extension.expect(DERDecoder.TYPE_OCTET_STRING);
        return new DERDecoder(extension.getBytes(extension.getLength()));
    }
}
