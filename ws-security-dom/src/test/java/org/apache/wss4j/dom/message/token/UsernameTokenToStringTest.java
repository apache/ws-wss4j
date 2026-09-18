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

package org.apache.wss4j.dom.message.token;

import org.apache.wss4j.common.util.SOAPUtil;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.engine.WSSConfig;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A UsernameToken object reaches a log line or an exception message far more readily than a
 * password does by any other route, so toString() must not hand the password over with it.
 */
public class UsernameTokenToStringTest {

    private static final String PASSWORD = "SuperSecretPassword123";

    public UsernameTokenToStringTest() {
        WSSConfig.init();
    }

    @Test
    public void testPlaintextPasswordIsRedacted() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        UsernameToken usernameToken = new UsernameToken(true, doc, WSConstants.PASSWORD_TEXT);
        usernameToken.setName("bob");
        usernameToken.setPassword(PASSWORD);

        String serialized = usernameToken.toString();

        assertFalse(serialized.contains(PASSWORD),
            "toString() must not disclose the password: " + serialized);
        assertTrue(serialized.contains("bob"),
            "toString() should still identify the token: " + serialized);
        assertTrue(serialized.contains("***"),
            "the password element should still be there, redacted: " + serialized);
    }

    /**
     * A password digest is not the password, but it is the value an offline attack runs against,
     * so it is withheld in the same way.
     */
    @Test
    public void testDigestPasswordIsRedacted() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        // the PASSWORD_DIGEST constructor adds the Nonce and Created itself
        UsernameToken usernameToken = new UsernameToken(true, doc, WSConstants.PASSWORD_DIGEST);
        usernameToken.setName("bob");
        usernameToken.setPassword(PASSWORD);

        String digest = usernameToken.getPassword();
        String serialized = usernameToken.toString();

        assertFalse(serialized.contains(PASSWORD), "toString() disclosed the password");
        assertFalse(serialized.contains(digest),
            "toString() must not disclose the password digest: " + serialized);
        assertTrue(serialized.contains("***"), serialized);
    }

    /**
     * Redaction happens on a copy: the token itself must be untouched, or the password would be
     * destroyed by the act of logging it.
     */
    @Test
    public void testRedactionDoesNotAlterTheToken() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        UsernameToken usernameToken = new UsernameToken(true, doc, WSConstants.PASSWORD_TEXT);
        usernameToken.setName("bob");
        usernameToken.setPassword(PASSWORD);

        usernameToken.toString();

        assertEquals(PASSWORD, usernameToken.getPassword(),
            "toString() must not modify the token it was called on");
        assertEquals(PASSWORD,
            usernameToken.getElement().getElementsByTagNameNS(
                WSConstants.WSSE_NS, WSConstants.PASSWORD_LN).item(0).getTextContent(),
            "toString() must not modify the underlying element");
    }

    /**
     * A UsernameToken carrying no password at all - the key derivation case - still serialises.
     */
    @Test
    public void testTokenWithoutPasswordIsUnaffected() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        UsernameToken usernameToken = new UsernameToken(true, doc, null);
        usernameToken.setName("bob");

        String serialized = usernameToken.toString();

        assertTrue(serialized.contains("bob"), serialized);
        assertFalse(serialized.contains("***"),
            "nothing to redact, so nothing should be redacted: " + serialized);
    }
}
