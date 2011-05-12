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
        processorChain.addProcessor(new SecurityHeaderOutputProcessor(securityProperties));

        for (int i = 0; i < securityProperties.getOutAction().length; i++) {
            Constants.Action action = securityProperties.getOutAction()[i];
            switch (action) {
                case TIMESTAMP: {
                    processorChain.addProcessor(new TimestampOutputProcessor(securityProperties));
                    break;
                }
                case SIGNATURE: {
                    SignatureOutputProcessor signatureOutputProcessor = new SignatureOutputProcessor(securityProperties);
                    processorChain.addProcessor(signatureOutputProcessor);
                    processorChain.addProcessor(new SignatureEndingOutputProcessor(securityProperties, signatureOutputProcessor));
                    break;
                }
                case ENCRYPT: {
                    EncryptOutputProcessor encryptOutputProcessor = new EncryptOutputProcessor(securityProperties);
                    processorChain.addProcessor(encryptOutputProcessor);
                    processorChain.addProcessor(new EncryptEndingOutputProcessor(securityProperties, encryptOutputProcessor));
                    break;
                }
                case USERNAMETOKEN: {
                    UsernameTokenOutputProcessor usernameTokenOutputProcessor = new UsernameTokenOutputProcessor(securityProperties);
                    processorChain.addProcessor(usernameTokenOutputProcessor);
                    break;
                }
                case USERNAMETOKEN_SIGN: {
                    UsernameTokenOutputProcessor usernameTokenOutputProcessor = new UsernameTokenOutputProcessor(securityProperties);
                    processorChain.addProcessor(usernameTokenOutputProcessor);
                    SignatureOutputProcessor signatureOutputProcessor = new SignatureOutputProcessor(securityProperties);
                    processorChain.addProcessor(signatureOutputProcessor);
                    processorChain.addProcessor(new SignatureEndingOutputProcessor(securityProperties, signatureOutputProcessor));
                    break;
                }
                case SIGNATURE_CONFIRMATION: {
                    SignatureConfirmationOutputProcessor signatureConfirmationOutputProcessor = new SignatureConfirmationOutputProcessor(securityProperties);
                    processorChain.addProcessor(signatureConfirmationOutputProcessor);
                    break;
                }
                case SAML_TOKEN_SIGNED: {
                    SAMLTokenOutputProcessor samlTokenOutputProcessor = new SAMLTokenOutputProcessor(securityProperties);
                    processorChain.addProcessor(samlTokenOutputProcessor);
                    SignatureOutputProcessor signatureOutputProcessor = new SignatureOutputProcessor(securityProperties);
                    processorChain.addProcessor(signatureOutputProcessor);
                    processorChain.addProcessor(new SignatureEndingOutputProcessor(securityProperties, signatureOutputProcessor));
                    break;
                }
                case SAML_TOKEN_UNSIGNED: {
                    SAMLTokenOutputProcessor samlTokenOutputProcessor = new SAMLTokenOutputProcessor(securityProperties);
                    processorChain.addProcessor(samlTokenOutputProcessor);
                }
            }
        }

        processorChain.addProcessor(new FinalOutputProcessor(outputStream, encoding, securityProperties));
        return new XMLSecurityStreamWriter(processorChain);
    }
}
