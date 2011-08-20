package org.swssf.impl.util;

import org.w3c.dom.ls.LSInput;

import java.io.InputStream;
import java.io.Reader;

/**
 * User: giger
 * Date: 5/28/11
 * Time: 8:08 PM
 * Copyright 2011 Marc Giger gigerstyle@gmx.ch
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
public class ConcreteLSInput implements LSInput {

    private Reader reader;
    private InputStream inputStream;
    private String stringData;
    private String systemId;
    private String publicId;
    private String baseURI;
    private String encoding;
    private boolean certifiedText;

    public Reader getCharacterStream() {
        return this.reader;
    }

    public void setCharacterStream(Reader characterStream) {
        this.reader = characterStream;
    }

    public InputStream getByteStream() {
        return this.inputStream;
    }

    public void setByteStream(InputStream byteStream) {
        this.inputStream = byteStream;
    }

    public String getStringData() {
        return this.stringData;
    }

    public void setStringData(String stringData) {
        this.stringData = stringData;
    }

    public String getSystemId() {
        return this.systemId;
    }

    public void setSystemId(String systemId) {
        this.systemId = systemId;
    }

    public String getPublicId() {
        return this.publicId;
    }

    public void setPublicId(String publicId) {
        this.publicId = publicId;
    }

    public String getBaseURI() {
        return this.baseURI;
    }

    public void setBaseURI(String baseURI) {
        this.baseURI = baseURI;
    }

    public String getEncoding() {
        return this.encoding;
    }

    public void setEncoding(String encoding) {
        this.encoding = encoding;
    }

    public boolean getCertifiedText() {
        return this.certifiedText;
    }

    public void setCertifiedText(boolean certifiedText) {
        this.certifiedText = certifiedText;
    }
}