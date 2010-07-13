package ch.gigerstyle.xmlsec.ext;

import java.security.Key;
import java.security.PublicKey;

/**
 * User: giger
 * Date: Jun 25, 2010
 * Time: 9:11:57 PM
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
public interface SecurityToken {

    public byte[] getSymmetricKey() throws XMLSecurityException;

    public Key getSecretKey() throws XMLSecurityException;

    public PublicKey getPublicKey() throws XMLSecurityException;

    public void verify() throws XMLSecurityException;
}
