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
package ch.gigerstyle.xmlsec.ext;

import java.security.Key;
import java.security.PublicKey;

/**
 * Sometimes it isn't known (@see EncryptedKeyInputProcessor) which kind of Token(Asymmetric, Symmetric)
 * we have at creation time. So we use a generic interface for both types.
 *
 * @author $Author$
 * @version $Revision$ $Date$
 */
public interface SecurityToken {

    public boolean isAsymmetric();

    public Key getSecretKey(String algorithmURI) throws XMLSecurityException;

    public PublicKey getPublicKey() throws XMLSecurityException;

    public void verify() throws XMLSecurityException;

    public SecurityToken getKeyWrappingToken();

    public String getKeyWrappingTokenAlgorithm();

    public Constants.KeyIdentifierType getKeyIdentifierType();
}
