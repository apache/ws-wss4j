/**
 * Copyright 2010, 2011 Marc Giger
 *
 * This file is part of the streaming-webservice-security-framework (swssf).
 *
 * The streaming-webservice-security-framework is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * The streaming-webservice-security-framework is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with the streaming-webservice-security-framework.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.swssf.impl.securityToken;

import org.swssf.crypto.Crypto;
import org.swssf.ext.Constants;
import org.swssf.ext.WSSecurityException;
import org.w3._2000._09.xmldsig_.X509DataType;

import javax.security.auth.callback.CallbackHandler;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class X509DataSecurityToken extends X509SecurityToken {
    private String alias = null;
    protected X509DataType x509DataType;

    X509DataSecurityToken(Crypto crypto, CallbackHandler callbackHandler, X509DataType x509DataType, String id, Object processor) {
        super(crypto, callbackHandler, id, processor);
        this.x509DataType = x509DataType;
    }

    protected String getAlias() throws WSSecurityException {
        if (this.alias == null) {
            this.alias = getCrypto().getAliasForX509Cert(x509DataType.getX509IssuerSerialType().getX509IssuerName(), x509DataType.getX509IssuerSerialType().getX509SerialNumber());
        }
        return this.alias;
    }

    public Constants.KeyIdentifierType getKeyIdentifierType() {
        return Constants.KeyIdentifierType.ISSUER_SERIAL;
    }
}
