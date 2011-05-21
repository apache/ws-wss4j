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
import org.apache.jcs.JCS;
import org.apache.jcs.access.exception.CacheException;
import org.apache.jcs.engine.ElementAttributes;
import org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_secext_1_0.UsernameTokenType;
import org.swssf.crypto.Crypto;
import org.swssf.ext.*;
import org.swssf.impl.securityToken.SecurityTokenFactory;
import org.swssf.securityEvent.SecurityEvent;
import org.swssf.securityEvent.UsernameTokenSecurityEvent;

import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;
import java.util.Calendar;
import java.util.Deque;
import java.util.GregorianCalendar;

/**
 * Processor for the UsernameToken XML Structure
 *
 * @author $Author: giger $
 * @version $Revision: 281 $ $Date: 2011-01-04 21:15:27 +0100 (Tue, 04 Jan 2011) $
 */
public class UsernameTokenInputHandler extends AbstractInputSecurityHeaderHandler {

    private static final String cacheRegionName = "usernameToken";

    private static JCS cache;

    static {
        try {
            cache = JCS.getInstance(cacheRegionName);
        } catch (CacheException e) {
            throw new RuntimeException(e);
        }
    }

    public UsernameTokenInputHandler(InputProcessorChain inputProcessorChain, final SecurityProperties securityProperties, Deque<XMLEvent> eventQueue, Integer index) throws WSSecurityException {

        final UsernameTokenType usernameTokenType = (UsernameTokenType) parseStructure(eventQueue, index);

        // If the UsernameToken is to be used for key derivation, the (1.1)
        // spec says that it cannot contain a password, and it must contain
        // an Iteration element
        if (usernameTokenType.getSalt() != null && (usernameTokenType.getPassword() != null || usernameTokenType.getIteration() == null)) {
            throw new WSSecurityException(WSSecurityException.INVALID_SECURITY_TOKEN, "badTokenType01");
        }

        Integer iteration = null;
        if (usernameTokenType.getIteration() != null) {
            iteration = Integer.parseInt(usernameTokenType.getIteration());
        }

        GregorianCalendar createdCal = null;
        byte[] nonceVal = null;

        Constants.UsernameTokenPasswordType usernameTokenPasswordType = Constants.UsernameTokenPasswordType.PASSWORD_NONE;
        if (usernameTokenType.getPasswordType() != null) {
            usernameTokenPasswordType = Constants.UsernameTokenPasswordType.getUsernameTokenPasswordType(usernameTokenType.getPasswordType());
        }

        final String username = usernameTokenType.getUsername();
        if (usernameTokenPasswordType == Constants.UsernameTokenPasswordType.PASSWORD_DIGEST) {
            final String nonce = usernameTokenType.getNonce();
            if (nonce == null || usernameTokenType.getCreated() == null) {
                throw new WSSecurityException(WSSecurityException.INVALID_SECURITY_TOKEN, "badTokenType01");
            }

            /*
                It is RECOMMENDED that used nonces be cached for a period at least as long as
                the timestamp freshness limitation period, above, and that UsernameToken with
                nonces that have already been used (and are thus in the cache) be rejected
            */
            final String cacheKey = nonce;
            if (cache.get(cacheKey) != null) {
                throw new WSSecurityException(WSSecurityException.FAILED_AUTHENTICATION);
            }
            ElementAttributes elementAttributes = new ElementAttributes();
            elementAttributes.setMaxLifeSeconds(300);
            try {
                cache.put(cacheKey, usernameTokenType.getCreated(), elementAttributes);
            } catch (CacheException e) {
                throw new WSSecurityException(WSSecurityException.FAILURE, null, e);
            }

            DatatypeFactory datatypeFactory = null;
            try {
                datatypeFactory = DatatypeFactory.newInstance();
            } catch (DatatypeConfigurationException e) {
                throw new WSSecurityException(WSSecurityException.FAILURE, null, e);
            }
            XMLGregorianCalendar xmlGregorianCalendar = datatypeFactory.newXMLGregorianCalendar(usernameTokenType.getCreated());
            createdCal = xmlGregorianCalendar.toGregorianCalendar();
            GregorianCalendar now = new GregorianCalendar();
            if (createdCal.after(now)) {
                throw new WSSecurityException(WSSecurityException.FAILED_AUTHENTICATION);
            }
            now.add(Calendar.MINUTE, 5);
            if (createdCal.after(now)) {
                throw new WSSecurityException(WSSecurityException.FAILED_AUTHENTICATION);
            }

            WSPasswordCallback pwCb = new WSPasswordCallback(username,
                    null,
                    usernameTokenType.getPasswordType(),
                    WSPasswordCallback.Usage.USERNAME_TOKEN);
            try {
                Utils.doPasswordCallback(securityProperties.getCallbackHandler(), pwCb);
            } catch (WSSecurityException e) {
                throw new WSSecurityException(WSSecurityException.FAILED_AUTHENTICATION, null, null, e);
            }

            if (pwCb.getPassword() == null) {
                throw new WSSecurityException(WSSecurityException.FAILED_AUTHENTICATION);
            }

            nonceVal = Base64.decodeBase64(nonce);

            String passDigest = Utils.doPasswordDigest(nonceVal, usernameTokenType.getCreated(), pwCb.getPassword());
            if (!usernameTokenType.getPassword().equals(passDigest)) {
                throw new WSSecurityException(WSSecurityException.FAILED_AUTHENTICATION);
            }
            usernameTokenType.setPassword(pwCb.getPassword());
        } else {
            WSPasswordCallback pwCb = new WSPasswordCallback(username,
                    usernameTokenType.getPassword(),
                    usernameTokenType.getPasswordType(),
                    WSPasswordCallback.Usage.USERNAME_TOKEN_UNKNOWN);
            try {
                Utils.doPasswordCallback(securityProperties.getCallbackHandler(), pwCb);
            } catch (WSSecurityException e) {
                throw new WSSecurityException(WSSecurityException.FAILED_AUTHENTICATION, null, e);
            }
            usernameTokenType.setPassword(pwCb.getPassword());
        }

        UsernameTokenSecurityEvent usernameTokenSecurityEvent = new UsernameTokenSecurityEvent(SecurityEvent.Event.UsernameToken);
        usernameTokenSecurityEvent.setUsername(username);
        usernameTokenSecurityEvent.setPassword(usernameTokenType.getPassword());
        usernameTokenSecurityEvent.setUsernameTokenPasswordType(usernameTokenPasswordType);
        usernameTokenSecurityEvent.setNonce(nonceVal);
        usernameTokenSecurityEvent.setCreated(createdCal);
        usernameTokenSecurityEvent.setSalt(usernameTokenType.getSalt());
        usernameTokenSecurityEvent.setIteration(iteration);
        inputProcessorChain.getSecurityContext().registerSecurityEvent(usernameTokenSecurityEvent);

        SecurityTokenProvider securityTokenProvider = new SecurityTokenProvider() {
            public SecurityToken getSecurityToken(Crypto crypto) throws WSSecurityException {
                return SecurityTokenFactory.newInstance().getSecurityToken(usernameTokenType, null);
            }

            public String getId() {
                return usernameTokenType.getId();
            }
        };
        inputProcessorChain.getSecurityContext().registerSecurityTokenProvider(usernameTokenType.getId(), securityTokenProvider);
    }

    @Override
    protected Parseable getParseable(StartElement startElement) {
        return new UsernameTokenType(startElement);
    }
}
