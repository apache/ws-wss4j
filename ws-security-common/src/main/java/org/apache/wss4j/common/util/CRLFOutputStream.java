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

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;

public class CRLFOutputStream extends FilterOutputStream {

    private static final byte CR = '\r';
    private static final byte LF = '\n';
    private static final byte[] CRLF = new byte[]{CR, LF};

    private boolean lastByteCR = false;

    public CRLFOutputStream(OutputStream out) {
        super(out);
    }

    @Override
    public void write(int b) throws IOException {
        if (b == CR) {
            out.write(CRLF);
            lastByteCR = true;
        } else if (b == LF) {
            if (lastByteCR) {
                lastByteCR = false;
            } else {
                out.write(CRLF);
            }
        } else {
            out.write(b);
            lastByteCR = false;
        }
    }

    @Override
    public void write(byte[] b, int off, int len) throws IOException {

        int start = off;
        for (int i = off; i < len; i++) {
            if (b[i] == CR) {
                out.write(b, start, i + 1 - start);
                out.write(LF);
                lastByteCR = true;
                start = i + 1;
            } else if (b[i] == LF) {
                if (lastByteCR) {
                    lastByteCR = false;
                    start++;
                } else {
                    int l = i - start;
                    if (l > 0) {
                        out.write(b, start, l);
                    }
                    out.write(CRLF);
                    start = i + 1;
                }
            } else {
                lastByteCR = false;
            }
        }
        out.write(b, start, len - start);
    }
}
