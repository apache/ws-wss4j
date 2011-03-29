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

import java.security.Key;
import java.security.PublicKey;

/**
 * This class represents the different token types which can occur in WS-Security
 * <p/>
 * Sometimes it isn't known (@see EncryptedKeyInputProcessor) which kind of Token(Asymmetric, Symmetric)
 * we have at creation time. So we use a generic interface for both types.
 *
 * @author $Author: giger $
 * @version $Revision: 281 $ $Date: 2011-01-04 21:15:27 +0100 (Tue, 04 Jan 2011) $
 */
public interface SecurityToken {

    /**
     * Returns the token type
     *
     * @return true if asymmetric token, false if symmetric token
     */
    public boolean isAsymmetric();

    /**
     * Returns the secret key
     *
     * @param algorithmURI for the requested key
     * @return The requested key for the specified algorithmURI, or null if no matching key is found
     * @throws WSSecurityException if the key can't be loaded
     */
    public Key getSecretKey(String algorithmURI) throws WSSecurityException;

    /**
     * Returns the public key if one exist for this token type
     *
     * @return The Public-Key for asymmetric algorithms
     * @throws WSSecurityException if the key can't be loaded
     */
    public PublicKey getPublicKey() throws WSSecurityException;

    /**
     * Verifies the key if applicable
     *
     * @throws WSSecurityException if the key couldn't be verified or the key isn't valid
     */
    public void verify() throws WSSecurityException;

    /**
     * Returns the key wrapping token
     *
     * @return The wrapping SecurityToken
     */
    public SecurityToken getKeyWrappingToken();

    /**
     * Returns the Key wrapping token's algorithm
     *
     * @return the KeyWrappingToken algorithm
     */
    public String getKeyWrappingTokenAlgorithm();

    /**
     * Returns the KeyIdentifierType
     *
     * @return the KeyIdentifierType
     */
    public Constants.KeyIdentifierType getKeyIdentifierType();
}
