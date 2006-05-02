/*
 * This source is a plain copy from bouncycastle software.
 * Thus:
 * Copyright (c) 2000 The Legion Of The Bouncy Castle (http://www.bouncycastle.org)
 */
package org.apache.ws.security.components.crypto;

/**
 * class for breaking up an X500 Name into it's component tokens, ala
 * java.util.StringTokenizer. We need this class as some of the
 * lightweight Java environment don't support classes like
 * StringTokenizer.
 */
public class X509NameTokenizer {
    private String oid;
    private int index;
    private StringBuffer buf = new StringBuffer();

    public X509NameTokenizer(String oid) {
        this.oid = oid;
        this.index = -1;
    }

    public boolean hasMoreTokens() {
        return (index != oid.length());
    }

    public String nextToken() {
        if (index == oid.length()) {
            return null;
        }

        int end = index + 1;
        boolean quoted = false;
        boolean escaped = false;

        buf.setLength(0);

        while (end != oid.length()) {
            char c = oid.charAt(end);

            if (c == '"') {
                if (!escaped) {
                    quoted = !quoted;
                } else {
                    buf.append(c);
                }
                escaped = false;
            } else {
                if (escaped || quoted) {
                    buf.append(c);
                    escaped = false;
                } else if (c == '\\') {
                    escaped = true;
                } else if (c == ',') {
                    break;
                } else {
                    buf.append(c);
                }
            }
            end++;
        }

        index = end;
        return buf.toString().trim();
    }
}
