package ch.gigerstyle.xmlsec;

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

    private MessageDigest messageDigest;

    public DigestOutputStream(MessageDigest messageDigest) {
        this.messageDigest = messageDigest;
    }

    public void write(byte[] arg0) {
        write(arg0, 0, arg0.length);
    }

    public void write(int arg0) {
        messageDigest.update((byte) arg0);

        System.out.print(new String(new byte[]{(byte)arg0}));
        System.out.flush();
    }

    public void write(byte[] arg0, int arg1, int arg2) {
        messageDigest.update(arg0, arg1, arg2);

        System.out.print(new String(arg0, arg1, arg2));
        System.out.flush();
        
    }

    public byte[] getDigestValue() {
        return messageDigest.digest();
    }
}
