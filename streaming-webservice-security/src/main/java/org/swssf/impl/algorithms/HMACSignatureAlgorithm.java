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
import org.xmlsecurity.ns.configuration.AlgorithmType;

import javax.crypto.Mac;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

/**
 * @author $Author: $
 * @version $Revision: $ $Date: $
 */
public class HMACSignatureAlgorithm implements SignatureAlgorithm {

    private AlgorithmType algorithmType;
    private Mac mac;

    public HMACSignatureAlgorithm(AlgorithmType algorithmType) throws NoSuchProviderException, NoSuchAlgorithmException {
        this.algorithmType = algorithmType;
        mac = Mac.getInstance(algorithmType.getJCEName(), algorithmType.getJCEProvider());
    }

    public void engineUpdate(byte[] input) throws WSSecurityException {
        mac.update(input);
    }

    public void engineUpdate(byte input) throws WSSecurityException {
        mac.update(input);
    }

    public void engineUpdate(byte[] buf, int offset, int len) throws WSSecurityException {
        mac.update(buf, offset, len);
    }

    public void engineInitSign(Key signingKey) throws WSSecurityException {
        try {
            mac.init(signingKey);
        } catch (InvalidKeyException e) {
            throw new WSSecurityException(WSSecurityException.FAILED_SIGNATURE, null, e);
        }
    }

    public void engineInitSign(Key signingKey, SecureRandom secureRandom) throws WSSecurityException {
        try {
            mac.init(signingKey);
        } catch (InvalidKeyException e) {
            throw new WSSecurityException(WSSecurityException.FAILED_SIGNATURE, null, e);
        }
    }

    public void engineInitSign(Key signingKey, AlgorithmParameterSpec algorithmParameterSpec) throws WSSecurityException {
        try {
            mac.init(signingKey, algorithmParameterSpec);
        } catch (InvalidKeyException e) {
            throw new WSSecurityException(WSSecurityException.FAILED_SIGNATURE, null, e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new WSSecurityException(WSSecurityException.FAILED_SIGNATURE, null, e);
        }
    }

    public byte[] engineSign() throws WSSecurityException {
        return mac.doFinal();
    }

    public void engineInitVerify(Key verificationKey) throws WSSecurityException {
        try {
            mac.init(verificationKey);
        } catch (InvalidKeyException e) {
            throw new WSSecurityException(WSSecurityException.FAILED_CHECK, null, e);
        }
    }

    public boolean engineVerify(byte[] signature) throws WSSecurityException {
        byte[] completeResult = mac.doFinal();
        return MessageDigest.isEqual(completeResult, signature);
    }

    public void engineSetParameter(AlgorithmParameterSpec params) throws WSSecurityException {
    }
}
