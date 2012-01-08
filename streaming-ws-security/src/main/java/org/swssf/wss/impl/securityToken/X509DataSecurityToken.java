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

import org.swssf.binding.xmldsig.X509DataType;
import org.swssf.binding.xmldsig.X509IssuerSerialType;
import org.swssf.wss.ext.WSSConstants;
import org.swssf.wss.ext.WSSecurityContext;
import org.swssf.xmlsec.crypto.Crypto;
import org.swssf.xmlsec.ext.XMLSecurityException;
import org.swssf.xmlsec.ext.XMLSecurityUtils;

import javax.security.auth.callback.CallbackHandler;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class X509DataSecurityToken extends X509SecurityToken {

    private String alias = null;
    protected X509DataType x509DataType;

    X509DataSecurityToken(WSSecurityContext wsSecurityContext, Crypto crypto, CallbackHandler callbackHandler,
                          X509DataType x509DataType, String id, WSSConstants.KeyIdentifierType keyIdentifierType, Object processor) {
        super(WSSConstants.X509V3Token, wsSecurityContext, crypto, callbackHandler, id, keyIdentifierType, processor);
        this.x509DataType = x509DataType;
    }

    protected String getAlias() throws XMLSecurityException {
        if (this.alias == null) {
            X509IssuerSerialType x509IssuerSerialType = XMLSecurityUtils.getQNameType(
                    x509DataType.getX509IssuerSerialOrX509SKIOrX509SubjectName(), WSSConstants.TAG_dsig_X509IssuerSerial);
            this.alias = getCrypto().getAliasForX509Cert(x509IssuerSerialType.getX509IssuerName(), x509IssuerSerialType.getX509SerialNumber());
        }
        return this.alias;
    }
}
