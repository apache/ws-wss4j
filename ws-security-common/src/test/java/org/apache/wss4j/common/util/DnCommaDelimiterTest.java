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

import static org.junit.jupiter.api.Assertions.assertEquals;

class DnCommaDelimiterTest {

	private static final String TYPICAL_CA ="CN=Entrust Certification Authority - L1K,OU=(c) 2012 Entrust\\, Inc. - for authorized use only,OU=See www.entrust.net/legal-terms,O=Entrust\\, Inc.,C=US";
	private static final String QUOTES_TYPICAL_CA ="CN=Entrust Certification Authority - L1K, OU=\"(c) 2012 Entrust, Inc. - for authorized use only\", OU=See www.entrust.net/legal-terms, O=\"Entrust, Inc.\", C=US";

	private DnCommaDelimiter subject = new  DnCommaDelimiter();


	@Test
	void whenMultipleAttributesArePresentThenSpaceIsPlacedAfterComma() {
		String actual = new DnCommaDelimiter().delimitRdnWithDoubleComma("CN=EOIR,OU=Some Unit,DC=Another place");
		assertEquals("CN=EOIR, OU=Some Unit, DC=Another place",actual);
	}
	@Test
	void whenRdnContainsACommaThenTheRdnIsSurroundedByDoubleQuotes() {
		String actual = new DnCommaDelimiter().delimitRdnWithDoubleComma(TYPICAL_CA);
		assertEquals(QUOTES_TYPICAL_CA,actual);
	}

	@Test
	void whenRdnIsInvalidThenExpectException() {
		Assertions.assertThrows(IllegalArgumentException.class, () -> {
			subject.delimitRdnWithDoubleComma("invalid");
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

}