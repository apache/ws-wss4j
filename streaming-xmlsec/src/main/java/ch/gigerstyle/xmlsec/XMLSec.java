package ch.gigerstyle.xmlsec;

import ch.gigerstyle.xmlsec.config.Init;
import ch.gigerstyle.xmlsec.ext.*;

import java.security.Provider;
import java.security.Security;

/**
 * User: giger
 * Date: May 13, 2010
 * Time: 2:01:16 PM
 * Copyright 2010 Marc Giger gigerstyle@gmx.ch
 * <p/>
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 * <p/>
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * <p/>
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */
public class XMLSec {

    //todo overall AccessController.doPrivileged

    //todo replace overall "BC" with getProvider somewhere

    static {

        try {
            Class c = XMLSec.class.getClassLoader().loadClass("org.bouncycastle.jce.provider.BouncyCastleProvider");
            if (null == Security.getProvider("BC")) {
                int i = Security.addProvider((Provider) c.newInstance());
            }
        } catch (Throwable e) {
            //todo: exception is not allowed here...
            throw new RuntimeException("Adding BouncyCastle provider failed", e);
        }
    }

    public static OutboundXMLSec getOutboundXMLSec(SecurityProperties securityProperties) throws XMLSecurityException, SecurityConfigurationException {
        if (securityProperties == null) {
            throw new XMLSecurityException("SecurityProperties must not be null!");
        }

        Init.init(null);

        securityProperties = validateAndApplyDefaultsToOutboundSecurityProperties(securityProperties);
        return new OutboundXMLSec(securityProperties);
    }

    public static InboundXMLSec getInboundXMLSec(SecurityProperties securityProperties) throws XMLSecurityException, SecurityConfigurationException {
        if (securityProperties == null) {
            throw new XMLSecurityException("SecurityProperties must not be null!");
        }

        Init.init(null);

        securityProperties = validateAndApplyDefaultsToInboundSecurityProperties(securityProperties);
        return new InboundXMLSec(securityProperties);
    }

    public static SecurityProperties validateAndApplyDefaultsToOutboundSecurityProperties(SecurityProperties securityProperties) throws SecurityConfigurationException {
        if (securityProperties.getOutAction() == null) {
            throw new SecurityConfigurationException("NoOutputAction");
        }
        for (int i = 0; i < securityProperties.getOutAction().length; i++) {
            Constants.Action action = securityProperties.getOutAction()[i];
            switch (action) {
                case TIMESTAMP:
                    if (securityProperties.getTimestampTTL() == null) {
                        securityProperties.setTimestampTTL(300);
                    }
                    break;
                case SIGNATURE:
                    if (securityProperties.getSignatureKeyStore() == null) {
                        throw new SecurityConfigurationException("NoSignatureKeyStore");
                    }
                    if (securityProperties.getSignatureUser() == null) {
                        throw new SecurityConfigurationException("NoSignatureUser");
                    }
                    if (securityProperties.getCallbackHandler() == null) {
                        throw new SecurityConfigurationException("NoCallbackHandler");
                    }
                    if (securityProperties.getSignatureSecureParts().isEmpty()) {
                        securityProperties.addSignaturePart(new SecurePart("Body", "http://schemas.xmlsoap.org/soap/envelope/", "Element"));
                    }
                    if (securityProperties.getSignatureAlgorithm() == null) {
                        securityProperties.setSignatureAlgorithm("http://www.w3.org/2000/09/xmldsig#rsa-sha1");
                    }
                    if (securityProperties.getSignatureDigestAlgorithm() == null) {
                        securityProperties.setSignatureDigestAlgorithm("http://www.w3.org/2000/09/xmldsig#sha1");
                    }
                    if (securityProperties.getSignatureCanonicalizationAlgorithm() == null) {
                        securityProperties.setSignatureCanonicalizationAlgorithm("http://www.w3.org/2001/10/xml-exc-c14n#");
                    }
                    if (securityProperties.getSignatureKeyIdentifierType() == null) {
                        securityProperties.setSignatureKeyIdentifierType(Constants.KeyIdentifierType.ISSUER_SERIAL);
                    }
                    break;

                case ENCRYPT:
                    if (securityProperties.getEncryptionUseThisCertificate() == null
                            && securityProperties.getEncryptionKeyStore() == null) {
                        throw new SecurityConfigurationException("NoEncryptionKeyStoreNorEncryptionUseThisCertificate");
                    }
                    if (securityProperties.getEncryptionUser() == null && securityProperties.getEncryptionUseThisCertificate() == null) {
                        throw new SecurityConfigurationException("NoEncryptionUser");
                    }
                    if (securityProperties.getEncryptionSecureParts().isEmpty()) {
                        securityProperties.addEncryptionPart(new SecurePart("Body", "http://schemas.xmlsoap.org/soap/envelope/", "Content"));
                    }
                    if (securityProperties.getEncryptionSymAlgorithm() == null) {
                        securityProperties.setEncryptionSymAlgorithm("http://www.w3.org/2001/04/xmlenc#aes256-cbc");
                    }
                    if (securityProperties.getEncryptionKeyTransportAlgorithm() == null) {
                        //todo constants and rsa-oaep as default for aes
                        //@see http://www.w3.org/TR/2002/REC-xmlenc-core-20021210/Overview.html#rsa-1_5 :
                        //"RSA-OAEP is RECOMMENDED for the transport of AES keys"
                        //@see http://www.w3.org/TR/2002/REC-xmlenc-core-20021210/Overview.html#rsa-oaep-mgf1p
                        securityProperties.setEncryptionKeyTransportAlgorithm("http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p");
                    }
                    if (securityProperties.getEncryptionKeyIdentifierType() == null) {
                        securityProperties.setEncryptionKeyIdentifierType(Constants.KeyIdentifierType.ISSUER_SERIAL);
                    }
                    break;
            }
        }
        //todo clone securityProperties
        return securityProperties;
    }

    public static SecurityProperties validateAndApplyDefaultsToInboundSecurityProperties(SecurityProperties securityProperties) throws SecurityConfigurationException {
        //todo clone securityProperties
        return securityProperties;
    }
}
