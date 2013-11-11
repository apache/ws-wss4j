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
import org.apache.wss4j.common.util.AttachmentUtils;

public class AttachmentTest {

    @org.junit.Test
    public void testMimeHeaderUncomment_1() throws Exception {
        Assert.assertEquals(
                "\"a\" \"(b)\" c  test",
                AttachmentUtils.uncomment("\"a\" \"(b)\" c ((\"d\")) test"));
    }

    @org.junit.Test
    public void testMimeHeaderUncomment_2() throws Exception {
        Assert.assertEquals(
                "",
                AttachmentUtils.uncomment("(\"a\" \"(b)\" c ((\"d\")) test)"));
    }

    @org.junit.Test
    public void testMimeHeaderUncomment_3() throws Exception {
        Assert.assertEquals(
                "\"a\" \"(\"b\")\" test",
                AttachmentUtils.uncomment("\"a\" \"(\"b\")\" (c(\"d\"))test"));
    }

    @org.junit.Test
    public void testMimeHeaderUnfold_1() throws Exception {
        Assert.assertEquals(
                "\r\n",
                AttachmentUtils.unfold("\r\n"));
    }

    @org.junit.Test
    public void testMimeHeaderUnfold_2() throws Exception {
        Assert.assertEquals(
                "\r\na",
                AttachmentUtils.unfold("\r\na"));
    }

    @org.junit.Test
    public void testMimeHeaderUnfold_3() throws Exception {
        Assert.assertEquals(
                "",
                AttachmentUtils.unfold("\r\n "));
    }

    @org.junit.Test
    public void testMimeHeaderUnfold_4() throws Exception {
        Assert.assertEquals(
                "",
                AttachmentUtils.unfold("\r\n\t"));
    }

    @org.junit.Test
    public void testMimeHeaderUnfold_5() throws Exception {
        Assert.assertEquals(
                "aa",
                AttachmentUtils.unfold("a\r\n\ta"));
    }

    @org.junit.Test
    public void testMimeHeaderUnfold_6() throws Exception {
        Assert.assertEquals(
                "aaa",
                AttachmentUtils.unfold("a\r\n\taa"));
    }

    @org.junit.Test
    public void testMimeHeaderUnfold_7() throws Exception {
        Assert.assertEquals(
                "aaaa",
                AttachmentUtils.unfold("\r\n\taaaa"));
    }

    @org.junit.Test
    public void testMimeHeaderUnfold_8() throws Exception {
        Assert.assertEquals(
                "a",
                AttachmentUtils.unfold("\r\n\ta\r\n "));
    }

    @org.junit.Test
    public void testMimeHeaderUnfold_9() throws Exception {
        Assert.assertEquals(
                "\r\n\ra",
                AttachmentUtils.unfold("\r\n\ra\r\n "));
    }

    @org.junit.Test
    public void testMimeHeaderUnfold_10() throws Exception {
        Assert.assertEquals(
                "\r\n",
                AttachmentUtils.unfold("\r\n \r\n \r\n"));
    }

    @org.junit.Test
    public void testMimeHeaderUnfoldWS_1() throws Exception {
        Assert.assertEquals(
                "a ",
                AttachmentUtils.unfoldWhitespace(" a "));
    }

    @org.junit.Test
    public void testMimeHeaderUnfoldWS_2() throws Exception {
        Assert.assertEquals(
                "",
                AttachmentUtils.unfoldWhitespace(""));
    }

    @org.junit.Test
    public void testMimeHeaderUnfoldWS_3() throws Exception {
        Assert.assertEquals(
                "",
                AttachmentUtils.unfoldWhitespace(" \t \t\t  "));
    }

    @org.junit.Test
    public void testMimeHeaderUnfoldWS_4() throws Exception {
        Assert.assertEquals(
                "a\ta\t  a",
                AttachmentUtils.unfoldWhitespace(" \t a\ta\t  a"));
    }

    @org.junit.Test
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

    @org.junit.Test
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

    @org.junit.Test
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

    @org.junit.Test
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

    @org.junit.Test
    public void testMimeHeaderUnquoteInnerText_1() throws Exception {
        Assert.assertEquals(
                "\"\\\"\\\"\\\\A\"",
                AttachmentUtils.unquoteInnerText(
                        "\\\"\"\"\\\\\\A\\\""
                )
        );
    }

    @org.junit.Test
    public void testMimeHeaderUnquoteInnerText_2() throws Exception {
        Assert.assertEquals(
                "\"a\"",
                AttachmentUtils.unquoteInnerText(
                        "\\\"a\\\""
                )
        );
    }
}
