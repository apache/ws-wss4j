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
package org.apache.wss4j.common.attachment;

import org.apache.wss4j.common.util.CRLFOutputStream;
import org.junit.Assert;

import java.io.ByteArrayOutputStream;
import java.util.Random;

public class CRLFOutputStreamTest {

    @org.junit.Test
    public void testBytePerByte() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        CRLFOutputStream crlfOutputStream = new CRLFOutputStream(baos);
        crlfOutputStream.write('\n');
        crlfOutputStream.write('\r');
        crlfOutputStream.write('\r');
        crlfOutputStream.write('\n');
        crlfOutputStream.write('\n');
        crlfOutputStream.write('\n');
        crlfOutputStream.write('\r');
        crlfOutputStream.write('\r');
        crlfOutputStream.write('\r');
        crlfOutputStream.write('a');
        crlfOutputStream.write('\n');
        crlfOutputStream.write('\r');
        crlfOutputStream.write('\n');
        crlfOutputStream.write('a');
        crlfOutputStream.write('a');
        crlfOutputStream.write('a');
        crlfOutputStream.close();
        Assert.assertArrayEquals("\r\n\r\n\r\n\r\n\r\n\r\n\r\n\r\na\r\n\r\naaa".getBytes(), baos.toByteArray());
    }

    @org.junit.Test
    public void testBytes() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        CRLFOutputStream crlfOutputStream = new CRLFOutputStream(baos);
        crlfOutputStream.write("\n\r\r\n\n\n\r\r\ra\n\r\naaa".getBytes());
        crlfOutputStream.close();
        Assert.assertArrayEquals("\r\n\r\n\r\n\r\n\r\n\r\n\r\n\r\na\r\n\r\naaa".getBytes(), baos.toByteArray());
    }

    @org.junit.Test
    public void testBytes1() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        CRLFOutputStream crlfOutputStream = new CRLFOutputStream(baos);
        crlfOutputStream.write("aaaaaaaaaa".getBytes());
        crlfOutputStream.close();
        Assert.assertArrayEquals("aaaaaaaaaa".getBytes(), baos.toByteArray());
    }

    @org.junit.Test
    public void testRandom() throws Exception {
        byte[] pool = new byte[] {'\r', '\n', 'a'};
        Random random = new Random();

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        CRLFOutputStream crlfOutputStream = new CRLFOutputStream(baos);

        ByteArrayOutputStream testString = new ByteArrayOutputStream();

        for (int h = 0; h < 10000; h++) {
            if (random.nextBoolean()) {
                byte b = pool[random.nextInt(pool.length)];
                testString.write(b);
                crlfOutputStream.write(b);
            } else {
                int byteCount = random.nextInt(1000);
                byte[] bytes = new byte[byteCount];
                for (int i = 0; i < byteCount; i++) {
                     bytes[i] = pool[random.nextInt(pool.length)];
                }
                testString.write(bytes);
                crlfOutputStream.write(bytes);
            }
        }

        crlfOutputStream.close();
        byte[] res = baos.toByteArray();
        for (int i = 0; i < res.length; i++) {
            byte re = res[i];
            if (re == '\r') {
                if (res[i + 1] != '\n') {
                    throw new Exception("Missing \\n in\n" + createEscapedString(res) + "\n input string: " + createEscapedString(testString.toByteArray()));
                }
            } else if (re == '\n') {
                if (res[i - 1] != '\r') {
                    throw new Exception("Missing \\r in\n" + createEscapedString(res) + "\n input string: " + createEscapedString(testString.toByteArray()));
                }
            }
        }
    }

    private String createEscapedString(byte[] bytes) {
        StringBuilder stringBuilder = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            byte aByte = bytes[i];
            if (aByte == '\r') {
                stringBuilder.append("\\r");
            } else if (aByte == '\n') {
                stringBuilder.append("\\n");
            } else {
                stringBuilder.append((char)aByte);
            }
        }
        return stringBuilder.toString();
    }
}
