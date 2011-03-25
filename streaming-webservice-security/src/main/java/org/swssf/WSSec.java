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
package org.swssf;

import org.swssf.config.Init;
import org.swssf.ext.*;

import java.security.Provider;
import java.security.Security;

/**
 * This is the central class of the streaming webservice-security framework.<br/>
 * Instances of the inbound and outbound security streams can be retrieved
 * with this class.
 *
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class WSSec {

    //todo replace overall "BC" with getProvider somewhere

    static {
        try {
            Class c = WSSec.class.getClassLoader().loadClass("org.bouncycastle.jce.provider.BouncyCastleProvider");
            if (null == Security.getProvider("BC")) {
                int i = Security.addProvider((Provider) c.newInstance());
            }
        } catch (Throwable e) {
            throw new RuntimeException("Adding BouncyCastle provider failed", e);
        }
    }

    /**
     * Creates and configures an outbound streaming security engine
     *
     * @param securityProperties The user-defined security configuration
     * @return A new OutboundWSSec
     * @throws org.swssf.ext.WSSecurityException           if the initialisation failed
     * @throws SecurityConfigurationException if the configuration is invalid
     */
    public static OutboundWSSec getOutboundWSSec(SecurityProperties securityProperties) throws WSSecurityException, SecurityConfigurationException {
        if (securityProperties == null) {
            throw new WSSecurityException("SecurityProperties must not be null!");
        }

        Init.init(null);

        securityProperties = validateAndApplyDefaultsToOutboundSecurityProperties(securityProperties);
        return new OutboundWSSec(securityProperties);
    }

    /**
     * Creates and configures an inbound streaming security engine
     *
     * @param securityProperties The user-defined security configuration
     * @return A new InboundWSSec
     * @throws org.swssf.ext.WSSecurityException           if the initialisation failed
     * @throws SecurityConfigurationException if the configuration is invalid
     */
    public static InboundWSSec getInboundWSSec(SecurityProperties securityProperties) throws WSSecurityException, SecurityConfigurationException {
        if (securityProperties == null) {
            throw new WSSecurityException("SecurityProperties must not be null!");
        }

        Init.init(null);

        securityProperties = validateAndApplyDefaultsToInboundSecurityProperties(securityProperties);
        return new InboundWSSec(securityProperties);
    }

    /**
     * Validates the user supplied configuration and applies default values as apropriate for the outbound security engine
     *
     * @param securityProperties The configuration to validate
     * @return The validated configuration
     * @throws SecurityConfigurationException if the configuration is invalid
     */
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

    /**
     * Validates the user supplied configuration and applies default values as apropriate for the inbound security engine
     *
     * @param securityProperties The configuration to validate
     * @return The validated configuration
     * @throws SecurityConfigurationException if the configuration is invalid
     */
    public static SecurityProperties validateAndApplyDefaultsToInboundSecurityProperties(SecurityProperties securityProperties) throws SecurityConfigurationException {
        //todo clone securityProperties
        return securityProperties;
    }
}
