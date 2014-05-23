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

package org.apache.wss4j.common.kerberos;

import java.security.Key;

import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSException;

/**
 * Encapsulates Kerberos token (service ticket) and secret key returned by
 * {@link KerberosClientExceptionAction}.
 * 
 * The secret key might be null, in which case it must be obtained from the current subject's 
 * {@link javax.security.auth.kerberos.KerberosTicket} private credential. 
 * 
 * @author bgde
 */
public class KerberosContext {
    private static final org.slf4j.Logger LOG =
        org.slf4j.LoggerFactory.getLogger(KerberosContext.class);

    private boolean disposed;
    private GSSContext gssContext;
    private byte[] kerberosToken;
    private Key secretKey;

    /**
     * @return The Kerberos service ticket bytes or null they are not available/set.
     * @throws IllegalStateException If this context was already disposed.
     */
    public byte[] getKerberosToken() {
        if (disposed) {
            throw new IllegalStateException("Kerberos context is disposed.");
        }

        return kerberosToken;
    }

    public void setKerberosToken(byte[] kerberosToken) {
        this.kerberosToken = kerberosToken;
    }

    /**
     * @return The secret session key, or null if it is not available.
     * In this case it must be obtained from the current subject's {@link javax.security.auth.kerberos.KerberosTicket KerberosTicket} private credential.
     * 
     * @see {@link javax.security.auth.kerberos.KerberosTicket#getSessionKey()}
     * @throws IllegalStateException If this context was already disposed.
     */
    public Key getSecretKey() {
        if (disposed) {
            throw new IllegalStateException("Kerberos context is disposed.");
        }
        return secretKey; 
    }

    public void setSecretKey(Key secretKey) {
        this.secretKey = secretKey;
    }

    /**
     * @return The GSSContext as initialized during Kerberos service ticket retrieval.
     * @throws IllegalStateException If this context was already disposed.
     */
    public GSSContext getGssContext() {
        if (disposed) {
            throw new IllegalStateException("Kerberos context is disposed.");
        }
        return this.gssContext;
    }

    public void setGssContext(GSSContext gssContext) {
        this.gssContext = gssContext;
    }

    /**
     * Destroys all data held in this context instance. After calling this method, 
     * an attempt to retrieve any field of this context instance will throw an IllegalArgumentException.
     */
    public void dispose() {
        if (!disposed) {
            if (kerberosToken != null) {
                for (int i = 0; i < kerberosToken.length; i++) {
                    kerberosToken[i] = 0;
                }
            }

            secretKey = null;

            if (gssContext != null) {
                try {
                    gssContext.dispose();
                }
                catch (GSSException e) {
                    LOG.error("Error disposing of the GSSContext", e);
                }
            }

            disposed = true;
        }
    }

    /**
     * Checks if this context instance is already destroyed.
     * @return
     */
    public boolean isDisposed() {
        return disposed;
    }
}
