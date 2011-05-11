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
package org.swssf.impl.processor.input;

import org.oasis_open.docs.ws_sx.ws_secureconversation._200512.DerivedKeyTokenType;
import org.swssf.config.JCEAlgorithmMapper;
import org.swssf.crypto.Crypto;
import org.swssf.ext.*;
import org.swssf.impl.derivedKey.DerivedKeyUtils;
import org.swssf.impl.securityToken.SAMLSecurityToken;
import org.swssf.impl.securityToken.SecurityTokenFactory;
import org.swssf.impl.securityToken.UsernameSecurityToken;

import javax.crypto.spec.SecretKeySpec;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;
import java.security.Key;
import java.security.PublicKey;
import java.util.Deque;

/**
 * Processor for the SecurityContextToken XML Structure
 *
 * @author $Author: giger $
 * @version $Revision: 281 $ $Date: 2011-01-04 21:15:27 +0100 (Tue, 04 Jan 2011) $
 */
public class DerivedKeyTokenInputHandler extends AbstractInputSecurityHeaderHandler {

    public DerivedKeyTokenInputHandler(InputProcessorChain inputProcessorChain, final SecurityProperties securityProperties, Deque<XMLEvent> eventQueue, Integer index) throws WSSecurityException {

        final DerivedKeyTokenType derivedKeyTokenType = (DerivedKeyTokenType) parseStructure(eventQueue, index);
        if (derivedKeyTokenType.getSecurityTokenReference() == null) {
            throw new WSSecurityException(WSSecurityException.FAILED_CHECK, "noReference");
        }
        final SecurityToken securityToken = SecurityTokenFactory.newInstance().getSecurityToken(
                derivedKeyTokenType.getSecurityTokenReference(),
                securityProperties.getDecryptionCrypto(),
                securityProperties.getCallbackHandler(),
                inputProcessorChain.getSecurityContext()
        );

        final SecurityToken derivedKeySecurityToken = new SecurityToken() {
            public boolean isAsymmetric() {
                return false;
            }

            public Key getSecretKey(String algorithmURI) throws WSSecurityException {
                byte[] secret;
                if (securityToken != null) {
                    if (securityToken instanceof UsernameSecurityToken) {
                        UsernameSecurityToken usernameSecurityToken = (UsernameSecurityToken) securityToken;
                        secret = usernameSecurityToken.generateDerivedKey(
                                usernameSecurityToken.getPassword(),
                                usernameSecurityToken.getSalt(),
                                usernameSecurityToken.getIteration()
                        );
                    } else if (securityToken instanceof SAMLSecurityToken) {
                        SAMLSecurityToken samlSecurityToken = (SAMLSecurityToken) securityToken;
                        secret = samlSecurityToken.getSamlKeyInfo().getSecret();
                    } else {
                        secret = securityToken.getSecretKey(algorithmURI).getEncoded();
                    }
                } else {
                    throw new WSSecurityException(WSSecurityException.FAILED_CHECK, "unsupportedKeyId");
                }
                byte[] nonce = derivedKeyTokenType.getNonce();
                if (nonce == null || nonce.length == 0) {
                    throw new WSSecurityException("Missing wsc:Nonce value");
                }
                byte[] keyBytes = DerivedKeyUtils.deriveKey(
                        derivedKeyTokenType.getAlgorithm(),
                        derivedKeyTokenType.getLabel(),
                        derivedKeyTokenType.getLength(),
                        secret,
                        nonce,
                        derivedKeyTokenType.getOffset()
                );
                String algo = JCEAlgorithmMapper.translateURItoJCEID(algorithmURI);
                return new SecretKeySpec(keyBytes, algo);
            }

            public PublicKey getPublicKey() throws WSSecurityException {
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
                return derivedKeySecurityToken;
            }

            public String getId() {
                return derivedKeyTokenType.getId();
            }
        };
        inputProcessorChain.getSecurityContext().registerSecurityTokenProvider(derivedKeyTokenType.getId(), securityTokenProvider);
    }

    @Override
    protected Parseable getParseable(StartElement startElement) {
        return new DerivedKeyTokenType(startElement);
    }
}
