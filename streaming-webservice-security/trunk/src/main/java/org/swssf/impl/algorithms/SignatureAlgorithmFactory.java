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
package org.swssf.impl.algorithms;

import org.swssf.config.JCEAlgorithmMapper;
import org.swssf.ext.WSSecurityException;
import org.xmlsecurity.ns.configuration.AlgorithmType;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class SignatureAlgorithmFactory {

    private static SignatureAlgorithmFactory instance = null;

    private SignatureAlgorithmFactory() {
    }

    public static synchronized SignatureAlgorithmFactory getInstance() {
        if (instance == null) {
            instance = new SignatureAlgorithmFactory();
        }
        return instance;
    }

    public SignatureAlgorithm getSignatureAlgorithm(String algoURI) throws WSSecurityException, NoSuchProviderException, NoSuchAlgorithmException {
        AlgorithmType algorithmType = JCEAlgorithmMapper.getAlgorithmMapping(algoURI);
        if (algorithmType == null) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.UNSUPPORTED_ALGORITHM, "unknownSignatureAlgorithm", algoURI);
        }
        String algorithmClass = algorithmType.getAlgorithmClass();
        if ("MAC".equalsIgnoreCase(algorithmClass)) {
            return new HMACSignatureAlgorithm(algorithmType);
        } else if ("Signature".equalsIgnoreCase(algorithmClass)) {
            return new PKISignatureAlgorithm(algorithmType);
        } else {
            return null;
        }
    }
}
