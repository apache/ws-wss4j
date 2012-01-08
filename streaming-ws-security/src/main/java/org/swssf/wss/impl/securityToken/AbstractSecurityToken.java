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
package org.swssf.wss.impl.securityToken;

import org.swssf.wss.ext.WSSConstants;
import org.swssf.wss.ext.WSSecurityContext;
import org.swssf.wss.securityEvent.AlgorithmSuiteSecurityEvent;
import org.swssf.xmlsec.crypto.Crypto;
import org.swssf.xmlsec.ext.SecurityToken;
import org.swssf.xmlsec.ext.XMLSecurityConstants;
import org.swssf.xmlsec.ext.XMLSecurityException;

import javax.crypto.SecretKey;
import javax.security.auth.callback.CallbackHandler;
import java.security.Key;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAKey;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public abstract class AbstractSecurityToken implements SecurityToken {

    private WSSecurityContext wsSecurityContext;
    private Crypto crypto;
    private CallbackHandler callbackHandler;
    private String id;
    private Object processor;
    private WSSConstants.KeyIdentifierType keyIdentifierType;

    public AbstractSecurityToken(WSSecurityContext wsSecurityContext, Crypto crypto, CallbackHandler callbackHandler,
                                 String id, WSSConstants.KeyIdentifierType keyIdentifierType, Object processor) {
        this.wsSecurityContext = wsSecurityContext;
        this.crypto = crypto;
        this.callbackHandler = callbackHandler;
        this.id = id;
        this.keyIdentifierType = keyIdentifierType;
        this.processor = processor;
    }

    public WSSConstants.KeyIdentifierType getKeyIdentifierType() {
        return keyIdentifierType;
    }

    public String getId() {
        return this.id;
    }

    public Object getProcessor() {
        return processor;
    }

    public Crypto getCrypto() {
        return crypto;
    }

    public CallbackHandler getCallbackHandler() {
        return callbackHandler;
    }

    protected abstract Key getKey(String algorithmURI, XMLSecurityConstants.KeyUsage keyUsage) throws XMLSecurityException;

    @Override
    public Key getSecretKey(String algorithmURI, XMLSecurityConstants.KeyUsage keyUsage) throws XMLSecurityException {
        Key key = getKey(algorithmURI, keyUsage);
        if (key != null && this.wsSecurityContext != null) {
            AlgorithmSuiteSecurityEvent algorithmSuiteSecurityEvent = new AlgorithmSuiteSecurityEvent();
            algorithmSuiteSecurityEvent.setAlgorithmURI(algorithmURI);
            algorithmSuiteSecurityEvent.setKeyUsage(keyUsage);
            if (key instanceof RSAKey) {
                algorithmSuiteSecurityEvent.setKeyLength(((RSAKey) key).getModulus().bitLength());
            } else if (key instanceof SecretKey) {
                algorithmSuiteSecurityEvent.setKeyLength(key.getEncoded().length * 8);
            } else {
                throw new XMLSecurityException(XMLSecurityException.ErrorCode.UNSUPPORTED_ALGORITHM, "invalidKeySize");
            }
            this.wsSecurityContext.registerSecurityEvent(algorithmSuiteSecurityEvent);
        }
        return key;
    }

    protected abstract PublicKey getPubKey(String algorithmURI, XMLSecurityConstants.KeyUsage keyUsage) throws XMLSecurityException;

    @Override
    public PublicKey getPublicKey(String algorithmURI, XMLSecurityConstants.KeyUsage keyUsage) throws XMLSecurityException {
        PublicKey publicKey = getPubKey(algorithmURI, keyUsage);
        if (publicKey != null) {
            AlgorithmSuiteSecurityEvent algorithmSuiteSecurityEvent = new AlgorithmSuiteSecurityEvent();
            algorithmSuiteSecurityEvent.setAlgorithmURI(algorithmURI);
            algorithmSuiteSecurityEvent.setKeyUsage(keyUsage);
            if (publicKey instanceof RSAKey) {
                algorithmSuiteSecurityEvent.setKeyLength(((RSAKey) publicKey).getModulus().bitLength());
            } else {
                throw new XMLSecurityException(XMLSecurityException.ErrorCode.UNSUPPORTED_ALGORITHM, "invalidKeySize");
            }
            wsSecurityContext.registerSecurityEvent(algorithmSuiteSecurityEvent);
        }
        return publicKey;
    }

    public X509Certificate[] getX509Certificates() throws XMLSecurityException {
        return null;
    }

    public void verify() throws XMLSecurityException {
    }
}
