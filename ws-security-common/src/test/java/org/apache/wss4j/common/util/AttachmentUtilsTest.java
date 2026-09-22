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

import org.apache.wss4j.common.ext.WSSecurityException;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * The attachment URI reaches getAttachmentId from the wire at most call sites, so every shape it
 * can take has to come back as a WSSecurityException rather than an unchecked one.
 */
public class AttachmentUtilsTest {

    @Test
    public void testAttachmentIdIsDecoded() throws Exception {
        assertEquals("attachment", AttachmentUtils.getAttachmentId("cid:attachment"));
        assertEquals("a b", AttachmentUtils.getAttachmentId("cid:a+b"));
        assertEquals("a b", AttachmentUtils.getAttachmentId("cid:a%20b"));
        assertEquals("", AttachmentUtils.getAttachmentId("cid:"));
    }

    @Test
    public void testUriShorterThanTheCidPrefixIsRejected() {
        // "".substring(4) is a StringIndexOutOfBoundsException, not a security fault
        for (String uri : new String[] {"", "c", "ci", "cid"}) {
            WSSecurityException ex =
                assertThrows(WSSecurityException.class, () -> AttachmentUtils.getAttachmentId(uri),
                             "Expected a rejection of " + "\"" + uri + "\"");
            assertEquals(WSSecurityException.ErrorCode.INVALID_SECURITY, ex.getErrorCode());
        }
    }

    @Test
    public void testUriThatIsNotAnAttachmentReferenceIsRejected() {
        for (String uri : new String[] {"#foo", "http://example.com/a", "CID:attachment", " cid:a"}) {
            WSSecurityException ex =
                assertThrows(WSSecurityException.class, () -> AttachmentUtils.getAttachmentId(uri),
                             "Expected a rejection of " + uri);
            assertEquals(WSSecurityException.ErrorCode.INVALID_SECURITY, ex.getErrorCode());
        }
    }

    @Test
    public void testNullUriIsRejected() {
        WSSecurityException ex =
            assertThrows(WSSecurityException.class, () -> AttachmentUtils.getAttachmentId(null));
        assertEquals(WSSecurityException.ErrorCode.INVALID_SECURITY, ex.getErrorCode());
    }

    @Test
    public void testMalformedEscapeIsRejected() {
        // URLDecoder raises IllegalArgumentException for these, which is unchecked
        for (String uri : new String[] {"cid:%", "cid:%zz", "cid:a%2"}) {
            WSSecurityException ex =
                assertThrows(WSSecurityException.class, () -> AttachmentUtils.getAttachmentId(uri),
                             "Expected a rejection of " + uri);
            assertEquals(WSSecurityException.ErrorCode.INVALID_SECURITY, ex.getErrorCode());
        }
    }
}
