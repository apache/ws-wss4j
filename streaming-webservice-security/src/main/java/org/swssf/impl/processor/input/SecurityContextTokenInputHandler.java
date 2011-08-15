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
package org.swssf.impl.processor.input;

import org.oasis_open.docs.ws_sx.ws_secureconversation._200512.SecurityContextTokenType;
import org.swssf.config.JCEAlgorithmMapper;
import org.swssf.crypto.Crypto;
import org.swssf.ext.*;

import javax.crypto.spec.SecretKeySpec;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;
import java.security.Key;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Deque;

/**
 * Processor for the SecurityContextToken XML Structure
 *
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class SecurityContextTokenInputHandler extends AbstractInputSecurityHeaderHandler {

    public SecurityContextTokenInputHandler(InputProcessorChain inputProcessorChain, final SecurityProperties securityProperties, Deque<XMLEvent> eventQueue, Integer index) throws WSSecurityException {

        final SecurityContextTokenType securityContextTokenType = (SecurityContextTokenType) parseStructure(eventQueue, index);

        final SecurityToken securityContextToken = new SecurityToken() {

            public String getId() {
                return securityContextTokenType.getId();
            }

            public Object getProccesor() {
                return null;
            }

            public boolean isAsymmetric() {
                return false;
            }

            public Key getSecretKey(String algorithmURI) throws WSSecurityException {
                String algo = JCEAlgorithmMapper.translateURItoJCEID(algorithmURI);
                WSPasswordCallback passwordCallback = new WSPasswordCallback(securityContextTokenType.getIdentifier(), WSPasswordCallback.Usage.SECURITY_CONTEXT_TOKEN);
                Utils.doSecretKeyCallback(securityProperties.getCallbackHandler(), passwordCallback, null);
                if (passwordCallback.getKey() == null) {
                    throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "noKey", securityContextTokenType.getId());
                }
                return new SecretKeySpec(passwordCallback.getKey(), algo);
            }

            public PublicKey getPublicKey() throws WSSecurityException {
                return null;
            }

            public X509Certificate[] getX509Certificates() throws WSSecurityException {
                return null;
            }

            public void verify() throws WSSecurityException {
            }

            public SecurityToken getKeyWrappingToken() {
                return null;
            }

            public String getKeyWrappingTokenAlgorithm() {
                return null;
            }

            public Constants.KeyIdentifierType getKeyIdentifierType() {
                return null;
            }
        };

        SecurityTokenProvider securityTokenProvider = new SecurityTokenProvider() {
            public SecurityToken getSecurityToken(Crypto crypto) throws WSSecurityException {
                return securityContextToken;
            }

            public String getId() {
                return securityContextTokenType.getId();
            }
        };
        inputProcessorChain.getSecurityContext().registerSecurityTokenProvider(securityContextTokenType.getId(), securityTokenProvider);

        //also register a SecurityProvider with the identifier. @see SecurityContexTest#testSCTKDKTSignAbsolute
        SecurityTokenProvider securityTokenProviderDirectReference = new SecurityTokenProvider() {
            public SecurityToken getSecurityToken(Crypto crypto) throws WSSecurityException {
                return securityContextToken;
            }

            public String getId() {
                return securityContextTokenType.getIdentifier();
            }
        };
        inputProcessorChain.getSecurityContext().registerSecurityTokenProvider(securityContextTokenType.getIdentifier(), securityTokenProviderDirectReference);
    }

    @Override
    protected Parseable getParseable(StartElement startElement) {
        return new SecurityContextTokenType(startElement);
    }
}
