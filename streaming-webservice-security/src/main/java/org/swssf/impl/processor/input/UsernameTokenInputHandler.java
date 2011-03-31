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

import org.apache.commons.codec.binary.Base64;
import org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_secext_1_0.UsernameTokenType;
import org.swssf.crypto.Crypto;
import org.swssf.ext.*;
import org.swssf.impl.SecurityTokenFactory;

import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Deque;

/**
 * Prozessor for the BinarySecurityToken XML Structure
 *
 * @author $Author: giger $
 * @version $Revision: 281 $ $Date: 2011-01-04 21:15:27 +0100 (Tue, 04 Jan 2011) $
 */
public class UsernameTokenInputHandler extends AbstractInputSecurityHeaderHandler {

    public UsernameTokenInputHandler(InputProcessorChain inputProcessorChain, final SecurityProperties securityProperties, Deque<XMLEvent> eventQueue, Integer index) throws WSSecurityException {

        final UsernameTokenType usernameTokenType = (UsernameTokenType) parseStructure(eventQueue, index);

        // If the UsernameToken is to be used for key derivation, the (1.1)
        // spec says that it cannot contain a password, and it must contain
        // an Iteration element
        if (usernameTokenType.getSalt() != null) {
            if (usernameTokenType.getPassword() != null || usernameTokenType.getIteration() == null) {
                throw new WSSecurityException(WSSecurityException.INVALID_SECURITY_TOKEN, "badTokenType01");
            }
            return;
        }

        boolean hashed = false;
        if (usernameTokenType.getPasswordType() != null && Constants.NS_PASSWORD_DIGEST.equals(usernameTokenType.getPasswordType())) {
            if (usernameTokenType.getNonce() == null || usernameTokenType.getCreated() == null) {
                throw new WSSecurityException(WSSecurityException.INVALID_SECURITY_TOKEN, "badTokenType01");
            }
            hashed = true;
        }

        if (hashed) {
            WSPasswordCallback pwCb = new WSPasswordCallback(usernameTokenType.getUsername(), null, usernameTokenType.getPasswordType(), WSPasswordCallback.USERNAME_TOKEN);
            try {
                Utils.doCallback(securityProperties.getCallbackHandler(), pwCb);
            } catch (WSSecurityException e) {
                throw new WSSecurityException(WSSecurityException.FAILED_AUTHENTICATION, null, null, e);
            }

            if (pwCb.getPassword() == null) {
                throw new WSSecurityException(WSSecurityException.FAILED_AUTHENTICATION);
            }

            String passDigest = doPasswordDigest(usernameTokenType.getNonce(), usernameTokenType.getCreated(), pwCb.getPassword());
            if (!usernameTokenType.getPassword().equals(passDigest)) {
                throw new WSSecurityException(WSSecurityException.FAILED_AUTHENTICATION);
            }
            usernameTokenType.setPassword(pwCb.getPassword());
        }
        else {
            WSPasswordCallback pwCb = new WSPasswordCallback(usernameTokenType.getUsername(), usernameTokenType.getPassword(), usernameTokenType.getPasswordType(), WSPasswordCallback.USERNAME_TOKEN_UNKNOWN);
            try {
                Utils.doCallback(securityProperties.getCallbackHandler(), pwCb);
            } catch (WSSecurityException e) {
                throw new WSSecurityException(WSSecurityException.FAILED_AUTHENTICATION, null, e);
            }
            usernameTokenType.setPassword(pwCb.getPassword());
        }

        //todo securityEvent

        SecurityTokenProvider securityTokenProvider = new SecurityTokenProvider() {
            public SecurityToken getSecurityToken(Crypto crypto) throws WSSecurityException {
                return SecurityTokenFactory.newInstance().getSecurityToken(usernameTokenType);
            }
        };
        inputProcessorChain.getSecurityContext().registerSecurityTokenProvider(usernameTokenType.getId(), securityTokenProvider);
    }

    private String doPasswordDigest(String nonce, String created, String password) throws WSSecurityException {
        try {
            byte[] b1 = nonce != null ? Base64.decodeBase64(nonce) : new byte[0];
            byte[] b2 = created != null ? created.getBytes("UTF-8") : new byte[0];
            byte[] b3 = password.getBytes("UTF-8");
            byte[] b4 = new byte[b1.length + b2.length + b3.length];
            int offset = 0;
            System.arraycopy(b1, 0, b4, offset, b1.length);
            offset += b1.length;

            System.arraycopy(b2, 0, b4, offset, b2.length);
            offset += b2.length;

            System.arraycopy(b3, 0, b4, offset, b3.length);

            MessageDigest sha = MessageDigest.getInstance("SHA-1");
            sha.reset();
            sha.update(b4);
            return new String(Base64.encodeBase64(sha.digest()));
        } catch (NoSuchAlgorithmException e) {
            logger.fatal(e.getMessage(), e);
            throw new WSSecurityException(WSSecurityException.FAILURE, "noSHA1availabe", null, e);
        } catch (UnsupportedEncodingException e) {
            logger.fatal(e.getMessage(), e);
        }
        return null;
    }

    @Override
    protected Parseable getParseable(StartElement startElement) {
        return new UsernameTokenType(startElement);
    }
}
