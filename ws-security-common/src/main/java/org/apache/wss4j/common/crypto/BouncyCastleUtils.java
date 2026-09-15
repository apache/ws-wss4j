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

public final class BouncyCastleUtils {
    private static final byte TYPE_CONTEXT_SPECIFIC_0 = (byte)0x80;
    private static final byte TYPE_CONTEXT_SPECIFIC_1 = (byte)0xA1;
    private static final byte TYPE_CONTEXT_SPECIFIC_2 = (byte)0x82;

    private BouncyCastleUtils() {
        // complete
    }

    public static byte[] getAuthorityKeyIdentifierBytes(X509Certificate cert) {
        byte[] extensionValue = cert.getExtensionValue("2.5.29.35"); //NOPMD
        if (extensionValue == null) {
            return new byte[0];
        }
        return getAuthorityKeyIdentifierBytes(extensionValue);
    }

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
            byte[] keyIdentifier = readOptionalValue(authorityKeyIdentifier, TYPE_CONTEXT_SPECIFIC_0);
            readOptionalValue(authorityKeyIdentifier, TYPE_CONTEXT_SPECIFIC_1);
            readOptionalValue(authorityKeyIdentifier, TYPE_CONTEXT_SPECIFIC_2);
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
        if (!decoder.hasRemaining() || !decoder.test(type)) {
            return null; //NOPMD - an absent optional value is distinct from an empty value
        }
        decoder.expect(type);
        int length = decoder.getLength();
        return decoder.getBytes(length);
    }

}
