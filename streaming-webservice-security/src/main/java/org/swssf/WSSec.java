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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * This is the central class of the streaming webservice-security framework.<br/>
 * Instances of the inbound and outbound security streams can be retrieved
 * with this class.
 *
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class WSSec {

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
     * @throws org.swssf.ext.WSSecurityException
     *          if the initialisation failed
     * @throws org.swssf.ext.WSSConfigurationException
     *          if the configuration is invalid
     */
    public static OutboundWSSec getOutboundWSSec(SecurityProperties securityProperties) throws WSSecurityException, WSSConfigurationException {
        if (securityProperties == null) {
            throw new WSSConfigurationException(WSSecurityException.FAILURE, "missingSecurityProperties");
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
     * @throws org.swssf.ext.WSSecurityException
     *          if the initialisation failed
     * @throws org.swssf.ext.WSSConfigurationException
     *          if the configuration is invalid
     */
    public static InboundWSSec getInboundWSSec(SecurityProperties securityProperties) throws WSSecurityException, WSSConfigurationException {
        if (securityProperties == null) {
            throw new WSSConfigurationException(WSSecurityException.FAILURE, "missingSecurityProperties");
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
     * @throws org.swssf.ext.WSSConfigurationException
     *          if the configuration is invalid
     */
    public static SecurityProperties validateAndApplyDefaultsToOutboundSecurityProperties(SecurityProperties securityProperties) throws WSSConfigurationException {
        if (securityProperties.getOutAction() == null) {
            throw new WSSConfigurationException(WSSecurityException.FAILURE, "noOutputAction");
        }

        //todo encrypt sigconf when original signature was encrypted
        int pos = Arrays.binarySearch(securityProperties.getOutAction(), Constants.Action.SIGNATURE_CONFIRMATION);
        if (pos >= 0) {
            if (Arrays.binarySearch(securityProperties.getOutAction(), Constants.Action.SIGNATURE) < 0) {
                List<Constants.Action> actionList = new ArrayList<Constants.Action>(securityProperties.getOutAction().length);
                actionList.addAll(Arrays.asList(securityProperties.getOutAction()));
                actionList.add(pos, Constants.Action.SIGNATURE);
                securityProperties.setOutAction(actionList.toArray(new Constants.Action[securityProperties.getOutAction().length + 1]));
            }
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
                        throw new WSSConfigurationException(WSSecurityException.FAILURE, "signatureKeyStoreNotSet");
                    }
                    if (securityProperties.getSignatureUser() == null) {
                        throw new WSSConfigurationException(WSSecurityException.FAILURE, "noSignatureUser");
                    }
                    if (securityProperties.getCallbackHandler() == null) {
                        throw new WSSConfigurationException(WSSecurityException.FAILURE, "noCallback");
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
                        throw new WSSConfigurationException(WSSecurityException.FAILURE, "encryptionKeyStoreNotSet");
                    }
                    if (securityProperties.getEncryptionUser() == null && securityProperties.getEncryptionUseThisCertificate() == null) {
                        throw new WSSConfigurationException(WSSecurityException.FAILURE, "noEncryptionUser");
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
                case USERNAMETOKEN:
                    if (securityProperties.getTokenUser() == null) {
                        throw new WSSConfigurationException(WSSecurityException.FAILURE, "noTokenUser");
                    }
                    if (securityProperties.getCallbackHandler() == null) {
                        throw new WSSConfigurationException(WSSecurityException.FAILURE, "noCallback");
                    }
                    if (securityProperties.getUsernameTokenPasswordType() == null) {
                        securityProperties.setUsernameTokenPasswordType(Constants.UsernameTokenPasswordType.PASSWORD_DIGEST);
                    }
                    break;
                case USERNAMETOKEN_SIGN:
                    if (securityProperties.getTokenUser() == null) {
                        throw new WSSConfigurationException(WSSecurityException.FAILURE, "noTokenUser");
                    }
                    securityProperties.setSignatureUser(null);
                    if (securityProperties.getCallbackHandler() == null) {
                        throw new WSSConfigurationException(WSSecurityException.FAILURE, "noCallback");
                    }
                    if (securityProperties.getSignatureSecureParts().isEmpty()) {
                        securityProperties.addSignaturePart(new SecurePart("Body", "http://schemas.xmlsoap.org/soap/envelope/", "Element"));
                    }
                    if (securityProperties.getSignatureAlgorithm() == null) {
                        securityProperties.setSignatureAlgorithm("http://www.w3.org/2000/09/xmldsig#hmac-sha1");
                    }
                    if (securityProperties.getSignatureDigestAlgorithm() == null) {
                        securityProperties.setSignatureDigestAlgorithm("http://www.w3.org/2000/09/xmldsig#sha1");
                    }
                    if (securityProperties.getSignatureCanonicalizationAlgorithm() == null) {
                        securityProperties.setSignatureCanonicalizationAlgorithm("http://www.w3.org/2001/10/xml-exc-c14n#");
                    }
                    securityProperties.setSignatureKeyIdentifierType(Constants.KeyIdentifierType.USERNAMETOKEN_SIGNED);
                    if (securityProperties.getUsernameTokenPasswordType() == null) {
                        securityProperties.setUsernameTokenPasswordType(Constants.UsernameTokenPasswordType.PASSWORD_DIGEST);
                    }
                    break;
                case SIGNATURE_CONFIRMATION:
                    securityProperties.addSignaturePart(new SecurePart(Constants.TAG_wsse11_SignatureConfirmation.getLocalPart(), Constants.TAG_wsse11_SignatureConfirmation.getNamespaceURI(), "Element"));
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
     * @throws org.swssf.ext.WSSConfigurationException
     *          if the configuration is invalid
     */
    public static SecurityProperties validateAndApplyDefaultsToInboundSecurityProperties(SecurityProperties securityProperties) throws WSSConfigurationException {
        //todo clone securityProperties
        return securityProperties;
    }
}
