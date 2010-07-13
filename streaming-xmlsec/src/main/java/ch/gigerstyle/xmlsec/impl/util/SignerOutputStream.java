/*
 * Copyright 1999-2008 The Apache Software Foundation.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package ch.gigerstyle.xmlsec.impl.util;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.OutputStream;
import java.security.Signature;
import java.security.SignatureException;

public class SignerOutputStream extends OutputStream {

    protected static final transient Log log = LogFactory.getLog(SignerOutputStream.class);

    private final Signature signature;

    public SignerOutputStream(Signature signature) {
        this.signature = signature;
    }

    public void write(byte[] arg0) {
        write(arg0, 0, arg0.length);        
    }

    public void write(int arg0) {
        try {
            signature.update((byte) arg0);
        } catch (SignatureException e) {
            throw new RuntimeException(e);
        }
    }

    public void write(byte[] arg0, int arg1, int arg2) {
        try {
            signature.update(arg0, arg1, arg2);
        } catch (SignatureException e) {
            throw new RuntimeException(e);
        }
    }

    public boolean verify(byte[] signatureValue) throws SignatureException {
        return signature.verify(signatureValue);
    }

    public byte[] sign() throws SignatureException {
        return signature.sign();
    }
}