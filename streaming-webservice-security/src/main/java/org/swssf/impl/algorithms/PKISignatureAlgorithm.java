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

import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

/**
 * @author $Author: $
 * @version $Revision: $ $Date: $
 */
public class PKISignatureAlgorithm implements SignatureAlgorithm {

    private AlgorithmType algorithmType;
    private Signature signature;

    public PKISignatureAlgorithm(AlgorithmType algorithmType) throws NoSuchProviderException, NoSuchAlgorithmException {
        this.algorithmType = algorithmType;
        signature = Signature.getInstance(algorithmType.getJCEName(), algorithmType.getJCEProvider());
    }

    public void engineUpdate(byte[] input) throws WSSecurityException {
        try {
            signature.update(input);
        } catch (SignatureException e) {
            throw new WSSecurityException(e.getMessage(), e);
        }
    }

    public void engineUpdate(byte input) throws WSSecurityException {
        try {
            signature.update(input);
        } catch (SignatureException e) {
            throw new WSSecurityException(e.getMessage(), e);
        }
    }

    public void engineUpdate(byte[] buf, int offset, int len) throws WSSecurityException {
        try {
            signature.update(buf, offset, len);
        } catch (SignatureException e) {
            throw new WSSecurityException(e.getMessage(), e);
        }
    }

    public void engineInitSign(Key signingKey) throws WSSecurityException {
        try {
            signature.initSign((PrivateKey) signingKey);
        } catch (InvalidKeyException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_SIGNATURE, e);
        }
    }

    public void engineInitSign(Key signingKey, SecureRandom secureRandom) throws WSSecurityException {
        try {
            signature.initSign((PrivateKey) signingKey, secureRandom);
        } catch (InvalidKeyException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_SIGNATURE, e);
        }
    }

    public void engineInitSign(Key signingKey, AlgorithmParameterSpec algorithmParameterSpec) throws WSSecurityException {
        try {
            signature.initSign((PrivateKey) signingKey);
        } catch (InvalidKeyException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_SIGNATURE, e);
        }
    }

    public byte[] engineSign() throws WSSecurityException {
        try {
            return signature.sign();
        } catch (SignatureException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_SIGNATURE, e);
        }
    }

    public void engineInitVerify(Key verificationKey) throws WSSecurityException {
        try {
            signature.initVerify((PublicKey) verificationKey);
        } catch (InvalidKeyException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_CHECK, e);
        }
    }

    public boolean engineVerify(byte[] signature) throws WSSecurityException {
        try {
            return this.signature.verify(signature);
        } catch (SignatureException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_CHECK, e);
        }
    }

    public void engineSetParameter(AlgorithmParameterSpec params) throws WSSecurityException {
        try {
            signature.setParameter(params);
        } catch (InvalidAlgorithmParameterException e) {
            throw new WSSecurityException(e.getMessage(), e);
        }
    }
}
