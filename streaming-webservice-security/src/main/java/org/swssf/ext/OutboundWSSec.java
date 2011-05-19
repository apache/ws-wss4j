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
package org.swssf.ext;

import org.swssf.impl.DocumentContextImpl;
import org.swssf.impl.OutputProcessorChainImpl;
import org.swssf.impl.XMLSecurityStreamWriter;
import org.swssf.impl.processor.output.*;
import org.swssf.securityEvent.SecurityEvent;
import org.swssf.securityEvent.SecurityEventListener;

import javax.xml.stream.XMLStreamWriter;
import java.io.OutputStream;
import java.util.List;

/**
 * Outbound Streaming-WebService-Security
 * An instance of this class can be retrieved over the WSSec class
 *
 * @author $Author: giger $
 * @version $Revision: 281 $ $Date: 2011-01-04 21:15:27 +0100 (Tue, 04 Jan 2011) $
 */
public class OutboundWSSec {

    private SecurityProperties securityProperties;

    public OutboundWSSec(SecurityProperties securityProperties) {
        this.securityProperties = securityProperties;
    }

    /**
     * This method is the entry point for the incoming security-engine.
     * Hand over the original XMLStreamReader and use the returned one for further processing
     *
     * @param outputStream The original outputStream
     * @return A new XMLStreamWriter which does transparently the security processing.
     * @throws WSSecurityException thrown when a Security failure occurs
     */
    public XMLStreamWriter processOutMessage(OutputStream outputStream, String encoding, List<SecurityEvent> requestSecurityEvents) throws WSSecurityException {
        return processOutMessage(outputStream, encoding, requestSecurityEvents, null);
    }

    /**
     * This method is the entry point for the incoming security-engine.
     * Hand over the original XMLStreamReader and use the returned one for further processing
     *
     * @param outputStream The original outputStream
     * @return A new XMLStreamWriter which does transparently the security processing.
     * @throws WSSecurityException thrown when a Security failure occurs
     */
    public XMLStreamWriter processOutMessage(OutputStream outputStream, String encoding, List<SecurityEvent> requestSecurityEvents, SecurityEventListener securityEventListener) throws WSSecurityException {

        final SecurityContextImpl securityContextImpl = new SecurityContextImpl();
        securityContextImpl.putList(SecurityEvent.class, requestSecurityEvents);
        securityContextImpl.setSecurityEventListener(securityEventListener);
        final DocumentContextImpl documentContext = new DocumentContextImpl();
        documentContext.setEncoding(encoding);

        OutputProcessorChainImpl processorChain = new OutputProcessorChainImpl(securityContextImpl, documentContext);
        processorChain.addProcessor(new SecurityHeaderOutputProcessor(securityProperties, null));

        for (int i = 0; i < securityProperties.getOutAction().length; i++) {
            Constants.Action action = securityProperties.getOutAction()[i];
            switch (action) {
                case TIMESTAMP: {
                    processorChain.addProcessor(new TimestampOutputProcessor(securityProperties, action));
                    break;
                }
                case SIGNATURE: {
                    processorChain.addProcessor(new BinarySecurityTokenOutputProcessor(securityProperties, action));
                    SignatureOutputProcessor signatureOutputProcessor = new SignatureOutputProcessor(securityProperties, action);
                    processorChain.addProcessor(signatureOutputProcessor);
                    processorChain.addProcessor(new SignatureEndingOutputProcessor(securityProperties, action, signatureOutputProcessor));
                    break;
                }
                case ENCRYPT: {
                    processorChain.addProcessor(new BinarySecurityTokenOutputProcessor(securityProperties, action));
                    processorChain.addProcessor(new EncryptedKeyOutputProcessor(securityProperties, action));
                    processorChain.addProcessor(new EncryptOutputProcessor(securityProperties, action));
                    processorChain.addProcessor(new EncryptEndingOutputProcessor(securityProperties, action));
                    break;
                }
                case USERNAMETOKEN: {
                    UsernameTokenOutputProcessor usernameTokenOutputProcessor = new UsernameTokenOutputProcessor(securityProperties, action);
                    processorChain.addProcessor(usernameTokenOutputProcessor);
                    break;
                }
                case USERNAMETOKEN_SIGN: {
                    processorChain.addProcessor(new UsernameTokenOutputProcessor(securityProperties, action));
                    SignatureOutputProcessor signatureOutputProcessor = new SignatureOutputProcessor(securityProperties, action);
                    processorChain.addProcessor(signatureOutputProcessor);
                    processorChain.addProcessor(new SignatureEndingOutputProcessor(securityProperties, action, signatureOutputProcessor));
                    break;
                }
                case SIGNATURE_CONFIRMATION: {
                    SignatureConfirmationOutputProcessor signatureConfirmationOutputProcessor = new SignatureConfirmationOutputProcessor(securityProperties, action);
                    processorChain.addProcessor(signatureConfirmationOutputProcessor);
                    break;
                }
                case SIGNATURE_WITH_DERIVED_KEY: {
                    processorChain.addProcessor(new BinarySecurityTokenOutputProcessor(securityProperties, action));
                    if (securityProperties.getDerivedKeyTokenReference() == Constants.DerivedKeyTokenReference.EncryptedKey) {
                        processorChain.addProcessor(new EncryptedKeyOutputProcessor(securityProperties, action));
                    } else if (securityProperties.getDerivedKeyTokenReference() == Constants.DerivedKeyTokenReference.SecurityContextToken) {
                        processorChain.addProcessor(new SecurityContextTokenOutputProcessor(securityProperties, action));
                    }
                    processorChain.addProcessor(new DerivedKeyTokenOutputProcessor(securityProperties, action));
                    SignatureOutputProcessor signatureOutputProcessor = new SignatureOutputProcessor(securityProperties, action);
                    processorChain.addProcessor(signatureOutputProcessor);
                    processorChain.addProcessor(new SignatureEndingOutputProcessor(securityProperties, action, signatureOutputProcessor));
                    break;
                }
                case ENCRYPT_WITH_DERIVED_KEY: {
                    processorChain.addProcessor(new BinarySecurityTokenOutputProcessor(securityProperties, action));
                    if (securityProperties.getDerivedKeyTokenReference() == Constants.DerivedKeyTokenReference.EncryptedKey) {
                        processorChain.addProcessor(new EncryptedKeyOutputProcessor(securityProperties, action));
                    } else if (securityProperties.getDerivedKeyTokenReference() == Constants.DerivedKeyTokenReference.SecurityContextToken) {
                        processorChain.addProcessor(new SecurityContextTokenOutputProcessor(securityProperties, action));
                    }
                    processorChain.addProcessor(new DerivedKeyTokenOutputProcessor(securityProperties, action));
                    processorChain.addProcessor(new EncryptOutputProcessor(securityProperties, action));
                    processorChain.addProcessor(new EncryptEndingOutputProcessor(securityProperties, action));
                    break;
                }
                case SAML_TOKEN_SIGNED: {
                    processorChain.addProcessor(new BinarySecurityTokenOutputProcessor(securityProperties, action));
                    processorChain.addProcessor(new SAMLTokenOutputProcessor(securityProperties, action));
                    SignatureOutputProcessor signatureOutputProcessor = new SignatureOutputProcessor(securityProperties, action);
                    processorChain.addProcessor(signatureOutputProcessor);
                    processorChain.addProcessor(new SignatureEndingOutputProcessor(securityProperties, action, signatureOutputProcessor));
                    break;
                }
                case SAML_TOKEN_UNSIGNED: {
                    processorChain.addProcessor(new SAMLTokenOutputProcessor(securityProperties, action));
                }
            }
        }

        processorChain.addProcessor(new FinalOutputProcessor(outputStream, encoding, securityProperties, null));
        return new XMLSecurityStreamWriter(processorChain);
    }
}
