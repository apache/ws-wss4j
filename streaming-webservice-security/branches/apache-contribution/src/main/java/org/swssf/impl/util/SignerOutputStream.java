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
package org.swssf.impl.util;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.swssf.ext.WSSecurityException;
import org.swssf.impl.algorithms.SignatureAlgorithm;

import java.io.OutputStream;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class SignerOutputStream extends OutputStream {

    protected static final transient Log log = LogFactory.getLog(SignerOutputStream.class);

    private final SignatureAlgorithm signatureAlgorithm;
    private StringBuffer stringBuffer;

    public SignerOutputStream(SignatureAlgorithm signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
        if (log.isDebugEnabled()) {
            stringBuffer = new StringBuffer();
        }
    }

    public void write(byte[] arg0) {
        write(arg0, 0, arg0.length);
    }

    public void write(int arg0) {
        try {
            signatureAlgorithm.engineUpdate((byte) arg0);
            if (log.isDebugEnabled()) {
                stringBuffer.append(new String(new byte[]{(byte) arg0}));
            }
        } catch (WSSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    public void write(byte[] arg0, int arg1, int arg2) {
        try {
            signatureAlgorithm.engineUpdate(arg0, arg1, arg2);
            if (log.isDebugEnabled()) {
                stringBuffer.append(new String(arg0, arg1, arg2));
            }
        } catch (WSSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    public boolean verify(byte[] signatureValue) throws WSSecurityException {
        if (log.isDebugEnabled()) {
            log.debug("Pre Signed: ");
            log.debug(stringBuffer.toString());
            log.debug("End pre Signed ");
            stringBuffer = new StringBuffer();
        }
        return signatureAlgorithm.engineVerify(signatureValue);
    }

    public byte[] sign() throws WSSecurityException {
        if (log.isDebugEnabled()) {
            log.debug("Pre Signed: ");
            log.debug(stringBuffer.toString());
            log.debug("End pre Signed ");
            stringBuffer = new StringBuffer();
        }
        return signatureAlgorithm.engineSign();
    }
}