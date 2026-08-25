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

import org.apache.wss4j.common.ext.WSSecurityException;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class DERDecoderTest {

    @Test
    public void testShortLengthValue() throws Exception {
        DERDecoder decoder = new DERDecoder(new byte[] {DERDecoder.TYPE_OCTET_STRING, 0x02, 0x01, 0x02});
        decoder.expect(DERDecoder.TYPE_OCTET_STRING);
        assertEquals(2, decoder.getLength());
        assertArrayEquals(new byte[] {0x01, 0x02}, decoder.getBytes(2));
        assertFalse(decoder.hasRemaining());
    }

    @Test
    public void testIndefiniteLength() throws Exception {
        DERDecoder decoder = new DERDecoder(new byte[] {DERDecoder.TYPE_SEQUENCE, (byte)0x80});
        decoder.expect(DERDecoder.TYPE_SEQUENCE);
        assertEquals(-1, decoder.getLength());
    }

    @Test
    public void testRejectsLengthLargerThanInteger() throws Exception {
        DERDecoder decoder = new DERDecoder(
            new byte[] {DERDecoder.TYPE_SEQUENCE, (byte)0x84, (byte)0x80, 0x00, 0x00, 0x00}
        );
        decoder.expect(DERDecoder.TYPE_SEQUENCE);
        assertThrows(WSSecurityException.class, decoder::getLength);
    }

    @Test
    public void testRejectsReadsAndSkipsBeyondRemainingData() throws Exception {
        DERDecoder decoder = new DERDecoder(new byte[] {0x01});
        assertTrue(decoder.hasRemaining());
        assertThrows(WSSecurityException.class, () -> decoder.getBytes(Integer.MAX_VALUE));
        assertThrows(WSSecurityException.class, () -> decoder.skip(Integer.MAX_VALUE));
    }
}
