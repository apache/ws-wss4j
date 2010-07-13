package ch.gigerstyle.xmlsec.impl;

import java.security.Key;

/**
 * User: giger
 * Date: Jun 4, 2010
 * Time: 11:18:04 PM
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
public class EncryptionPartDef {

    public enum Modifier {
        Element("http://www.w3.org/2001/04/xmlenc#Element"),
        Content("http://www.w3.org/2001/04/xmlenc#Content");

        private String modifier;

        Modifier(String modifier) {
            this.modifier = modifier;
        }

        public String getModifier() {
            return this.modifier; 
        }
    }

    private Modifier modifier;
    private Key symmetricKey;
    private String keyId;
    private String encRefId;

    public Modifier getModifier() {
        return modifier;
    }

    public void setModifier(Modifier modifier) {
        this.modifier = modifier;
    }

    public Key getSymmetricKey() {
        return symmetricKey;
    }

    public void setSymmetricKey(Key symmetricKey) {
        this.symmetricKey = symmetricKey;
    }

    public String getKeyId() {
        return keyId;
    }

    public void setKeyId(String keyId) {
        this.keyId = keyId;
    }

    public String getEncRefId() {
        return encRefId;
    }

    public void setEncRefId(String encRefId) {
        this.encRefId = encRefId;
    }
}
