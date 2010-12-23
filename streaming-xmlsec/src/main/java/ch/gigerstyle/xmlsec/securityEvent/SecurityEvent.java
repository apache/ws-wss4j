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
package ch.gigerstyle.xmlsec.securityEvent;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public abstract class SecurityEvent {

    public enum Event {
        Operation,
        Timestamp,
        SignedPart,
        SignedElement,
        InitiatorEncryptionToken,
        RecipientEncryptionToken,
        AlgorithmSuite,
        EncryptedPart,
        EncryptedElement,
        ContentEncrypted,
    }

    private Event securityEventType;

    protected SecurityEvent(Event securityEventType) {
        this.securityEventType = securityEventType;
    }

    public Event getSecurityEventType() {
        return securityEventType;
    }

    public void setSecurityEventType(Event securityEventType) {
        this.securityEventType = securityEventType;
    }
}
