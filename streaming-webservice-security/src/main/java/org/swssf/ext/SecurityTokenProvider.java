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
package org.swssf.ext;

import org.swssf.crypto.Crypto;

/**
 * A SecurityTokenProvider is a object which provides a Token for cryptographic operations
 * @author $Author: giger $
 * @version $Revision: 281 $ $Date: 2011-01-04 21:15:27 +0100 (Tue, 04 Jan 2011) $
 */
public interface SecurityTokenProvider {

    /**
     * Returns the represented SecurityToken of this object
     * @param crypto The Crypto to use to restore the Token
     * @return The SecurityToken
     * @throws XMLSecurityException if the token couldn't be loaded
     */
    public SecurityToken getSecurityToken(Crypto crypto) throws XMLSecurityException;
}
