package ch.gigerstyle.xmlsec;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.OutputStream;
import java.security.MessageDigest;

/**
 * User: giger
 * Date: May 14, 2010
 * Time: 6:51:04 PM
 * Copyright 2010 Marc Giger gigerstyle@gmx.ch
 * <p/>
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 * <p/>
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * <p/>
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */
public class DigestOutputStream extends OutputStream {

    protected static final transient Log log = LogFactory.getLog(DigestOutputStream.class);

    private MessageDigest messageDigest;

    private StringBuffer stringBuffer;

    public DigestOutputStream(MessageDigest messageDigest) {
        this.messageDigest = messageDigest;
        if (log.isDebugEnabled()) {
            stringBuffer = new StringBuffer();
        }
    }

    public void write(byte[] arg0) {
        write(arg0, 0, arg0.length);
    }

    public void write(int arg0) {
        messageDigest.update((byte) arg0);
        if (log.isDebugEnabled()) {
            stringBuffer.append(new String(new byte[]{(byte)arg0}));
        }
    }

    public void write(byte[] arg0, int arg1, int arg2) {
        messageDigest.update(arg0, arg1, arg2);
        if (log.isDebugEnabled()) {
            stringBuffer.append(new String(arg0, arg1, arg2));
        }
    }

    public byte[] getDigestValue() {
        if (log.isDebugEnabled()) {
            log.debug("Pre Digest: ");
            log.debug(stringBuffer.toString());
            log.debug("End pre Digest ");
            stringBuffer = new StringBuffer();
        }
        return messageDigest.digest();
    }
}
