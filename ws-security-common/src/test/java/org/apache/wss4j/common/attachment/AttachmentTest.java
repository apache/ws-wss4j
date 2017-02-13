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

import org.junit.Assert;
import org.junit.Test;
import org.apache.wss4j.common.util.AttachmentUtils;

public class AttachmentTest {

    @Test
    public void testMatch() {
        Assert.assertTrue("text/xml".matches("(?i)(text/xml).*"));
        Assert.assertTrue("TEXT/XML".matches("(?i)(text/xml).*"));
        Assert.assertTrue("application/xml".matches("(?i)(application/xml).*"));
        Assert.assertTrue("APPLICATION/XML".matches("(?i)(application/xml).*"));
        Assert.assertTrue("text/plain".matches("(?i)(text/).*"));
        Assert.assertTrue("TEXT/PLAIN".matches("(?i)(text/).*"));
    }

    @Test
    public void testMimeHeaderUncomment_1() throws Exception {
        Assert.assertEquals(
                "\"a\" \"(b)\" c  test",
                AttachmentUtils.uncomment("\"a\" \"(b)\" c ((\"d\")) test"));
    }

    @Test
    public void testMimeHeaderUncomment_2() throws Exception {
        Assert.assertEquals(
                "",
                AttachmentUtils.uncomment("(\"a\" \"(b)\" c ((\"d\")) test)"));
    }

    @Test
    public void testMimeHeaderUncomment_3() throws Exception {
        Assert.assertEquals(
                "\"a\" \"(\"b\")\" test",
                AttachmentUtils.uncomment("\"a\" \"(\"b\")\" (c(\"d\"))test"));
    }

    @Test
    public void testMimeHeaderUnfold_1() throws Exception {
        Assert.assertEquals(
                "\r\n",
                AttachmentUtils.unfold("\r\n"));
    }

    @Test
    public void testMimeHeaderUnfold_2() throws Exception {
        Assert.assertEquals(
                "\r\na",
                AttachmentUtils.unfold("\r\na"));
    }

    @Test
    public void testMimeHeaderUnfold_3() throws Exception {
        Assert.assertEquals(
                "",
                AttachmentUtils.unfold("\r\n "));
    }

    @Test
    public void testMimeHeaderUnfold_4() throws Exception {
        Assert.assertEquals(
                "",
                AttachmentUtils.unfold("\r\n\t"));
    }

    @Test
    public void testMimeHeaderUnfold_5() throws Exception {
        Assert.assertEquals(
                "aa",
                AttachmentUtils.unfold("a\r\n\ta"));
    }

    @Test
    public void testMimeHeaderUnfold_6() throws Exception {
        Assert.assertEquals(
                "aaa",
                AttachmentUtils.unfold("a\r\n\taa"));
    }

    @Test
    public void testMimeHeaderUnfold_7() throws Exception {
        Assert.assertEquals(
                "aaaa",
                AttachmentUtils.unfold("\r\n\taaaa"));
    }

    @Test
    public void testMimeHeaderUnfold_8() throws Exception {
        Assert.assertEquals(
                "a",
                AttachmentUtils.unfold("\r\n\ta\r\n "));
    }

    @Test
    public void testMimeHeaderUnfold_9() throws Exception {
        Assert.assertEquals(
                "\r\n\ra",
                AttachmentUtils.unfold("\r\n\ra\r\n "));
    }

    @Test
    public void testMimeHeaderUnfold_10() throws Exception {
        Assert.assertEquals(
                "\r\n",
                AttachmentUtils.unfold("\r\n \r\n \r\n"));
    }

    @Test
    public void testMimeHeaderUnfoldWS_1() throws Exception {
        Assert.assertEquals(
                "a ",
                AttachmentUtils.unfoldWhitespace(" a "));
    }

    @Test
    public void testMimeHeaderUnfoldWS_2() throws Exception {
        Assert.assertEquals(
                "",
                AttachmentUtils.unfoldWhitespace(""));
    }

    @Test
    public void testMimeHeaderUnfoldWS_3() throws Exception {
        Assert.assertEquals(
                "",
                AttachmentUtils.unfoldWhitespace(" \t \t\t  "));
    }

    @Test
    public void testMimeHeaderUnfoldWS_4() throws Exception {
        Assert.assertEquals(
                "a\ta\t  a",
                AttachmentUtils.unfoldWhitespace(" \t a\ta\t  a"));
    }

    @Test
    public void testMimeHeaderDecodeRfc2184_1() throws Exception {
        Assert.assertEquals(
                "message/external-body;access-type=\"URL\";" +
                        "test=\"true\";" +
                        "url=\"ftp://cs.utk.edu/pub/moore/bulk-mailer/bulk-mailer.tar\""
                ,
                AttachmentUtils.decodeRfc2184(
                        "Message/External-Body; access-type=URL;" +
                                "URL*0=\"ftp://\";" +
                                "URL*1=\"cs.utk.edu/pub/moore/bulk-mailer/bulk-mailer.tar\";" +
                                "test=true"));
    }

    @Test
    public void testMimeHeaderDecodeRfc2184_2() throws Exception {
        Assert.assertEquals(
                "message/external-body;access-type=\"URL\";" +
                        "url=\"ftp://cs.utk.edu/pub/moore/bulk-mailer/bulk-mailer.tar\"",
                AttachmentUtils.decodeRfc2184(
                        "Message/External-Body; access-type=URL;" +
                                "URL*0=\"ftp://\";" +
                                "URL*1=\"cs.utk.edu/pub/moore/bulk-mailer/bulk-mailer.tar\""
                )
        );
    }

    @Test
    public void testMimeHeaderDecodeRfc2184_3() throws Exception {
        Assert.assertEquals(
                "application/x-stuff;" +
                        "title=\"This is ***fun***\"",
                AttachmentUtils.decodeRfc2184(
                        "application/x-stuff;" +
                                "title*=us-ascii'en-us'This%20is%20%2A%2A%2Afun%2A%2A%2A"
                )
        );
    }

    @Test
    public void testMimeHeaderDecodeRfc2184_4() throws Exception {
        Assert.assertEquals(
                "application/x-stuff;" +
                        "title=\"This is even more ***fun*** isn't it!\"",
                AttachmentUtils.decodeRfc2184(
                        "application/x-stuff;" +
                                "title*1*=us-ascii'en'This%20is%20even%20more%20;" +
                                "title*2*=%2A%2A%2Afun%2A%2A%2A%20;" +
                                "title*3=\"isn't it!\""
                )
        );
    }

    @Test
    public void testMimeHeaderUnquoteInnerText_1() throws Exception {
        Assert.assertEquals(
                "\"\\\"\\\"\\\\A\"",
                AttachmentUtils.unquoteInnerText(
                        "\\\"\"\"\\\\\\A\\\""
                )
        );
    }

    @Test
    public void testMimeHeaderUnquoteInnerText_2() throws Exception {
        Assert.assertEquals(
                "\"a\"",
                AttachmentUtils.unquoteInnerText(
                        "\\\"a\\\""
                )
        );
    }
}
