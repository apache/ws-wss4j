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
package org.swssf.impl.algorithms;

import org.swssf.ext.WSSecurityException;

import java.security.Key;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

/**
 * @author $Author: $
 * @version $Revision: $ $Date: $
 */
public interface SignatureAlgorithm {

    public void engineUpdate(byte[] input) throws WSSecurityException;

    public void engineUpdate(byte input) throws WSSecurityException;

    public void engineUpdate(byte buf[], int offset, int len) throws WSSecurityException;

    public void engineInitSign(Key signingKey) throws WSSecurityException;

    public void engineInitSign(Key signingKey, SecureRandom secureRandom) throws WSSecurityException;

    public void engineInitSign(Key signingKey, AlgorithmParameterSpec algorithmParameterSpec) throws WSSecurityException;

    public byte[] engineSign() throws WSSecurityException;

    public void engineInitVerify(Key verificationKey) throws WSSecurityException;

    public boolean engineVerify(byte[] signature) throws WSSecurityException;

    public void engineSetParameter(AlgorithmParameterSpec params) throws WSSecurityException;
}
