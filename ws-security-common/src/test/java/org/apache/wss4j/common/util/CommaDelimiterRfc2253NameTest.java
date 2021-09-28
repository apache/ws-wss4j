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

package org.apache.wss4j.common.util;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.security.auth.x500.X500Principal;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CommaDelimiterRfc2253NameTest {

	private static final String TYPICAL_CA ="CN=Entrust Certification Authority - L1K,OU=(c) 2012 Entrust\\, Inc. - for authorized use only,OU=See www.entrust.net/legal-terms,O=Entrust\\, Inc.,C=US";
	private static final String QUOTES_TYPICAL_CA ="CN=Entrust Certification Authority - L1K, OU=\"(c) 2012 Entrust, Inc. - for authorized use only\", OU=See www.entrust.net/legal-terms, O=\"Entrust, Inc.\", C=US";

	private CommaDelimiterRfc2253Name subject = new CommaDelimiterRfc2253Name();


	@Test
	void whenMultipleAttributesArePresentThenSpaceIsPlacedAfterComma() {
		String actual = new CommaDelimiterRfc2253Name().execute("CN=EOIR,OU=Some Unit,DC=Another place");
		assertEquals("CN=EOIR, OU=Some Unit, DC=Another place",actual);
	}
	@Test
	void whenRdnContainsACommaThenTheRdnIsSurroundedByDoubleQuotes() {
		String actual = new CommaDelimiterRfc2253Name().execute(TYPICAL_CA);
		assertEquals(QUOTES_TYPICAL_CA,actual);
	}

	@Test
	void whenRdnIsInvalidThenExpectException() {
		Assertions.assertThrows(IllegalArgumentException.class, () -> {
			subject.execute("invalid");
		});
	}


	@Test
	void whenCallingUnescapeWithStringNoEscapesThenNoChangesAreMade() throws Exception {
		String input = "This is a string with (c) no escaped! sStrings $";
		String actual = subject.unEscapeRfc2253RdnSubPart(input);
		assertEquals(input,actual,"Expect that string is unchanged");
	}


	@Test
	void whenCallingUnescapeWithStringThenItUnescapesAppropiateCharacters() throws Exception {
		String input = "This is a string with escapes \\,\\; \\\\ and \\< then \\> \\\"Copyright Apache\\\" ";
		String expected = "This is a string with escapes ,; \\ and < then > \"Copyright Apache\" ";
		String actual = subject.unEscapeRfc2253RdnSubPart(input);
		assertEquals(expected,actual,"Expect that string is unescaped");
	}


	@Test
	void whenCallingUnescapeWithStringWithMultiValueRdnThenItUnescapesAppropriateCharacters() throws Exception {
		String input = "OU=Sales\\+CN=J. Smith\\,O=Widget Inc.\\,C=US";
		String expected = "OU=Sales+CN=J. Smith,O=Widget Inc.,C=US";
		String actual = subject.unEscapeRfc2253RdnSubPart(input);
		assertEquals(expected,actual,"Expect that string is unescaped");
	}

	@Test
	public void testThatACommaDelimitedDnStringAndABackSlashEscapedDnProducesTheSameX509PrincipalUsingDefaultTruststore()
			throws KeyStoreException, InvalidAlgorithmParameterException, CertificateException, NoSuchAlgorithmException, IOException {
		KeyStore keystore = loadDefaultKeyStore();
		PKIXParameters params = new PKIXParameters(keystore);
		for (TrustAnchor ta : params.getTrustAnchors()) {
			X509Certificate cert = ta.getTrustedCert();
			assertThatTransformIsEquivalent(cert.getSubjectX500Principal().getName());
		}
	}

	private void assertThatTransformIsEquivalent(String dnString) {
		// The expected value below recreates what is done in the token class by recreating the  X500Principal using getName()
		// even though the calling methods already used a X500Principal.getName()  to pass the value in the first place ,
		// this seems wasteful but I believe there is a reason for this in the wss4j code ...
		// Searching for different RFC 2253 parsers , this one :
		// https://www.codeproject.com/Articles/9788/An-RFC-2253-Compliant-Distinguished-Name-Parser
		// mentioned that its not possible to recreate the original binary because of the RFC allows multibyte characters  using # encoding.
		// Indeed w/o this additional calls to X500Principal.getName() this test will fail for one of the CA which indeed uses # encoding
		// because the equals uses the X500Name.canonicalDn string for comparison which if used directly from the keystore would
		// still contain the multibyte characters.
		// Since wss4j does not send multibyte characters, this tests uses of new X500Principal(dnString)
		// accurately reflects change usage.

		X500Principal expected = new X500Principal(dnString);
		X500Principal recreatedX509principal = new X500Principal(subject.execute(dnString));
		assertEquals(expected, recreatedX509principal);
	}

	private KeyStore loadDefaultKeyStore() throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException {
		String filename = System.getProperty("java.home") + "/lib/security/cacerts".replace('/', File.separatorChar);
		FileInputStream is = new FileInputStream(filename);
		KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
		String password = "changeit";
		keystore.load(is, password.toCharArray());
		return keystore;
	}


}