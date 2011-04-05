/*
 * Copyright 1996-2011 itServe AG. All rights reserved.
 *
 * This software is the proprietary information of itServe AG
 * Bern Switzerland. Use is subject to license terms.
 *
 */
package org.swssf.impl.algorithms;

import org.swssf.config.JCEAlgorithmMapper;
import org.swssf.ext.WSSecurityException;
import org.xmlsecurity.ns.configuration.AlgorithmType;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

/**
 *
 * @author $Author: $
 * @version $Revision: $ $Date: $
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
            throw new WSSecurityException(WSSecurityException.UNSUPPORTED_ALGORITHM, "unknownSignatureAlgorithm", new Object[]{algoURI});
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
