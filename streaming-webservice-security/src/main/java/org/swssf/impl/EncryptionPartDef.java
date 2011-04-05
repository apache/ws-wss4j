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
package org.swssf.impl;

import org.swssf.ext.SecurePart;

import java.security.Key;

/**
 * EncryptionPartDef holds information about parts to be encrypt
 *
 * @author $Author: giger $
 * @version $Revision: 281 $ $Date: 2011-01-04 21:15:27 +0100 (Tue, 04 Jan 2011) $
 */
public class EncryptionPartDef {

    private SecurePart.Modifier modifier;
    private Key symmetricKey;
    private String keyId;
    private String encRefId;

    public SecurePart.Modifier getModifier() {
        return modifier;
    }

    public void setModifier(SecurePart.Modifier modifier) {
        this.modifier = modifier;
    }

    public Key getSymmetricKey() {
        return symmetricKey;
    }

    public void setSymmetricKey(Key symmetricKey) {
        this.symmetricKey = symmetricKey;
    }

    public String getKeyId() {
        return keyId;
    }

    public void setKeyId(String keyId) {
        this.keyId = keyId;
    }

    public String getEncRefId() {
        return encRefId;
    }

    public void setEncRefId(String encRefId) {
        this.encRefId = encRefId;
    }
}
