/*
 * Copyright 1996-2011 itServe AG. All rights reserved.
 *
 * This software is the proprietary information of itServe AG
 * Bern Switzerland. Use is subject to license terms.
 *
 */
package org.swssf.impl.derivedKey;

import org.apache.commons.codec.binary.Base64;
import org.swssf.ext.Constants;
import org.swssf.ext.WSSecurityException;

/**
 * @author $Author: $
 * @version $Revision: $ $Date: $
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
