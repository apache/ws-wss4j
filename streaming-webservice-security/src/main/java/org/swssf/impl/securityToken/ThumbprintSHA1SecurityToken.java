/**
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.swssf.impl.securityToken;

import org.swssf.crypto.Crypto;
import org.swssf.ext.Constants;
import org.swssf.ext.WSSecurityException;

import javax.security.auth.callback.CallbackHandler;

/**
 * @author $Author: $
 * @version $Revision: $ $Date: $
 */
public class ThumbprintSHA1SecurityToken extends X509SecurityToken {
    private String alias = null;
    private byte[] binaryContent;

    ThumbprintSHA1SecurityToken(Crypto crypto, CallbackHandler callbackHandler, byte[] binaryContent, String id, Object processor) {
        super(crypto, callbackHandler, id, processor);
        this.binaryContent = binaryContent;
    }

    protected String getAlias() throws WSSecurityException {
        if (this.alias == null) {
            this.alias = getCrypto().getAliasForX509CertThumb(binaryContent);
        }
        return this.alias;
    }

    public Constants.KeyIdentifierType getKeyIdentifierType() {
        return Constants.KeyIdentifierType.THUMBPRINT_IDENTIFIER;
    }
}
