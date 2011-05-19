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
import org.swssf.ext.SecurityToken;

import javax.security.auth.callback.CallbackHandler;

/**
 * @author $Author: $
 * @version $Revision: $ $Date: $
 */
public abstract class AbstractSecurityToken implements SecurityToken {

    private Crypto crypto;
    private CallbackHandler callbackHandler;
    private String id;
    private Object processor;

    AbstractSecurityToken(Crypto crypto, CallbackHandler callbackHandler, String id, Object processor) {
        this.crypto = crypto;
        this.callbackHandler = callbackHandler;
        this.id = id;
        this.processor = processor;
    }

    public String getId() {
        return this.id;
    }

    public Object getProccesor() {
        return processor;
    }

    public Crypto getCrypto() {
        return crypto;
    }

    public CallbackHandler getCallbackHandler() {
        return callbackHandler;
    }
}
