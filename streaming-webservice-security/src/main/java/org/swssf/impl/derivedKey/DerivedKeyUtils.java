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
package org.swssf.impl.derivedKey;

import org.apache.commons.codec.binary.Base64;
import org.swssf.ext.Constants;
import org.swssf.ext.WSSecurityException;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class DerivedKeyUtils {

    /**
     * Derive a key from this DerivedKeyToken instance
     *
     * @param length
     * @param secret
     * @throws org.swssf.ext.WSSecurityException
     *
     */
    public static byte[] deriveKey(String algorithm, String label, int length, byte[] secret, byte[] nonce, int offset) throws WSSecurityException {
        try {
            if (algorithm == null || algorithm.equals("")) {
                algorithm = Constants.P_SHA_1;
            }
            DerivationAlgorithm algo = AlgoFactory.getInstance(algorithm);
            byte[] labelBytes;
            if (label == null || label.length() == 0) {
                labelBytes = (Constants.WS_SecureConversation_DEFAULT_LABEL + Constants.WS_SecureConversation_DEFAULT_LABEL).getBytes("UTF-8");
            } else {
                labelBytes = label.getBytes("UTF-8");
            }

            nonce = Base64.decodeBase64(nonce);
            byte[] seed = new byte[labelBytes.length + nonce.length];
            System.arraycopy(labelBytes, 0, seed, 0, labelBytes.length);
            System.arraycopy(nonce, 0, seed, labelBytes.length, nonce.length);

            if (length <= 0) {
                length = 32;
            }
            return algo.createKey(secret, seed, offset, length);

        } catch (Exception e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, e);
        }
    }
}
