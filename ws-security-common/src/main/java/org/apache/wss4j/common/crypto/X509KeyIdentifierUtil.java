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
 * Decodes the X.509 key identifier extensions.
 */
public final class X509KeyIdentifierUtil {
    /** AuthorityKeyIdentifier keyIdentifier [0] IMPLICIT KeyIdentifier - primitive, context-specific 0. */
    private static final byte TAG_KEY_IDENTIFIER = (byte)0x80;
    /** AuthorityKeyIdentifier authorityCertIssuer [1] GeneralNames - constructed, context-specific 1. */
    private static final byte TAG_AUTHORITY_CERT_ISSUER = (byte)0xA1;
    /** AuthorityKeyIdentifier authorityCertSerialNumber [2] IMPLICIT CertificateSerialNumber -
     *  primitive, context-specific 2. */
    private static final byte TAG_AUTHORITY_CERT_SERIAL_NUMBER = (byte)0x82;

    private X509KeyIdentifierUtil() {
        // complete
    }

    /**
     * Read the keyIdentifier of the AuthorityKeyIdentifier extension (2.5.29.35) of the
     * given certificate.
     * <p>
     * X.509 extensions are required to use DER; BER encodings are rejected.
     *
     * @param cert the certificate to read the AuthorityKeyIdentifier from.
     * @return an empty array if the certificate has no AuthorityKeyIdentifier extension, null if
     *         the extension is present but carries no keyIdentifier, otherwise the keyIdentifier.
     * @throws IllegalArgumentException if the extension is present but is not valid DER.
     */
    public static byte[] getAuthorityKeyIdentifierBytes(X509Certificate cert) {
        byte[] extensionValue = cert.getExtensionValue("2.5.29.35"); //NOPMD
        if (extensionValue == null) {
            return new byte[0];
        }
        return getAuthorityKeyIdentifierBytes(extensionValue);
    }

    /**
     * Read the SubjectKeyIdentifier extension (2.5.29.14) of the given certificate.
     * <p>
     * X.509 extensions are required to use DER; BER encodings are rejected.
     *
     * @param cert the certificate to read the SubjectKeyIdentifier from.
     * @return an empty array if the certificate has no SubjectKeyIdentifier extension, otherwise
     *         the key identifier.
     * @throws IllegalArgumentException if the extension is present but is not valid DER.
     */
    public static byte[] getSubjectKeyIdentifierBytes(X509Certificate cert) {
        byte[] extensionValue = cert.getExtensionValue("2.5.29.14"); //NOPMD
        if (extensionValue == null) {
            return new byte[0];
        }
        return getSubjectKeyIdentifierBytes(extensionValue);
    }

    static byte[] getAuthorityKeyIdentifierBytes(byte[] extensionValue) {
        try {
            byte[] extensionBytes = readExtensionValue(extensionValue, DERDecoder.TYPE_SEQUENCE);
            if (extensionBytes.length == 0) {
                return null; //NOPMD - AuthorityKeyIdentifier#getKeyIdentifier returns null when absent
            }
            DERDecoder authorityKeyIdentifier = new DERDecoder(extensionBytes);
            byte[] keyIdentifier = readOptionalValue(authorityKeyIdentifier, TAG_KEY_IDENTIFIER);
            // The remaining fields are not used by WSS4J, but must still be well formed.
            skipOptionalValue(authorityKeyIdentifier, TAG_AUTHORITY_CERT_ISSUER);
            skipOptionalValue(authorityKeyIdentifier, TAG_AUTHORITY_CERT_SERIAL_NUMBER);
            authorityKeyIdentifier.expectEnd();
            return keyIdentifier;
        } catch (WSSecurityException ex) {
            throw new IllegalArgumentException("Invalid AuthorityKeyIdentifier extension", ex);
        }
    }

    static byte[] getSubjectKeyIdentifierBytes(byte[] extensionValue) {
        try {
            return readExtensionValue(extensionValue, DERDecoder.TYPE_OCTET_STRING);
        } catch (WSSecurityException ex) {
            throw new IllegalArgumentException("Invalid SubjectKeyIdentifier extension", ex);
        }
    }

    private static byte[] readExtensionValue(byte[] extensionValue, byte extensionType)
        throws WSSecurityException {
        DERDecoder extension = new DERDecoder(extensionValue);
        extension.expect(DERDecoder.TYPE_OCTET_STRING);
        int extensionLength = extension.getLength();
        byte[] extensionBytes = extension.getBytes(extensionLength);
        extension.expectEnd();

        DERDecoder extensionContents = new DERDecoder(extensionBytes);
        extensionContents.expect(extensionType);
        int extensionContentsLength = extensionContents.getLength();
        byte[] contents = extensionContents.getBytes(extensionContentsLength);
        extensionContents.expectEnd();
        return contents;
    }

    private static byte[] readOptionalValue(DERDecoder decoder, byte type) throws WSSecurityException {
        if (!startsWith(decoder, type)) {
            return null; //NOPMD - an absent optional value is distinct from an empty value
        }
        decoder.expect(type);
        int length = decoder.getLength();
        return decoder.getBytes(length);
    }

    private static void skipOptionalValue(DERDecoder decoder, byte type) throws WSSecurityException {
        if (!startsWith(decoder, type)) {
            return;
        }
        decoder.expect(type);
        int length = decoder.getLength();
        decoder.skip(length);
    }

    private static boolean startsWith(DERDecoder decoder, byte type) throws WSSecurityException {
        return decoder.hasRemaining() && decoder.test(type);
    }

}
