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

package wssec;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import java.security.cert.X509Certificate;

import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.ws.security.util.Base64;


/**
 * This is a test for WSS-300 - "SubjectKeyIdentifier (SKI) incorrectly calculated for 2048-bit RSA key".
 * The SKI value WSS4J generates for various key sizes is tested against the output from openssl, e.g.:
 * 
 * openssl x509 -inform der -ocspid -in wss40_server.crt | grep 'Public key OCSP hash' 
 * | perl -ne 'split; print pack("H*",$_[4])' | base64
 */
public class TestWSSecuritySKI extends TestCase {

    /**
     * TestWSSecurity constructor
     * <p/>
     * 
     * @param name name of the test
     */
    public TestWSSecuritySKI(String name) {
        super(name);
    }

    /**
     * JUnit suite
     * <p/>
     * 
     * @return a junit test suite
     */
    public static Test suite() {
        return new TestSuite(TestWSSecuritySKI.class);
    }
    
    public void testRSA2048() throws Exception {
        // Load the keystore
        Crypto crypto = CryptoFactory.getInstance("rsa2048.properties");
        X509Certificate[] certs = crypto.getCertificates("test");
        assertTrue(certs != null && certs.length > 0);
        
        byte[] skiBytes = crypto.getSKIBytesFromCert(certs[0]);
        String knownBase64Encoding = "tgkZUMZ461ZSA1nZkBu6E5GDxLM=";
        assertTrue(knownBase64Encoding.equals(Base64.encode(skiBytes)));
    }
    
}
