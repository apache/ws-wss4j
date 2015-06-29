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

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;

public final class BouncyCastleUtils {
    
    private BouncyCastleUtils() {
        // complete
    }

    public static byte[] getAuthorityKeyIdentifierBytes(X509Certificate cert) {
        byte[] extensionValue = cert.getExtensionValue("2.5.29.35"); //NOPMD
        if (extensionValue != null) {
            byte[] octets = ASN1OctetString.getInstance(extensionValue).getOctets();     
            AuthorityKeyIdentifier authorityKeyIdentifier = 
                AuthorityKeyIdentifier.getInstance(octets);
            return authorityKeyIdentifier.getKeyIdentifier();
        }
        return null;
    }
    
    public static byte[] getSubjectKeyIdentifierBytes(X509Certificate cert) {
        byte[] extensionValue = cert.getExtensionValue("2.5.29.14"); //NOPMD
        if (extensionValue != null) {
            byte[] subjectOctets = 
                ASN1OctetString.getInstance(extensionValue).getOctets();     
            SubjectKeyIdentifier subjectKeyIdentifier =
                SubjectKeyIdentifier.getInstance(subjectOctets);
            return subjectKeyIdentifier.getKeyIdentifier();
        }
        return null;
    }
    
}


