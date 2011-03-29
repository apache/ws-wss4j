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

import javax.xml.namespace.QName;
import java.util.List;

/**
 * This class holds per document, context informations 
 * @author $Author: giger $
 * @version $Revision: 281 $ $Date: 2011-01-04 21:15:27 +0100 (Tue, 04 Jan 2011) $
 */
public interface DocumentContext {

    /**
     * @return The Encoding of the Document
     */
    public String getEncoding();

    /**
     * @return The SOAP Version used
     */
    public String getSOAPMessageVersionNamespace();

    /**
     * Adds a Element to the path
     *
     * @param qName The QName of the path element
     */
    public void addPathElement(QName qName);

    /**
     * Removes a element from the path
     *
     * @return the removed element
     */
    public QName removePathElement();

    /**
     * @return The actual path in the xml
     */
    public List<QName> getPath();

    /**
     * Returns the parent element of the actual eventtype
     *
     * @param eventType current event type
     * @return the name of the parent element
     */
    public QName getParentElement(int eventType);

    /**
     * Indicates if we are currently processing the soap header
     *
     * @return true if we stay in the soap header, false otherwise
     */
    public boolean isInSOAPHeader();

    /**
     * Indicates if we are currently processing the soap body
     *
     * @return true if we stay in the soap body, false otherwise
     */
    public boolean isInSOAPBody();

    /**
     * @return The current level in the document
     */
    public int getDocumentLevel();

    /**
     * Indicates if we are currently processing the security header
     *
     * @return true if we stay in the security header, false otherwise
     */
    public boolean isInSecurityHeader();

    /**
     * Specifies that we are now in the security header
     *
     * @param inSecurityHeader set to true when we entering the security header, false otherwise
     */
    public void setInSecurityHeader(boolean inSecurityHeader);

    /**
     * Indicates if we currently stay in an encrypted content
     */
    public void setIsInEncryptedContent();

    /**
     * unset when we leave the encrypted content
     */
    public void unsetIsInEncryptedContent();

    /**
     * @return true if we currently stay in encrypted content
     */
    public boolean isInEncryptedContent();

    /**
     * Indicates if we currently stay in a signed content
     */
    public void setIsInSignedContent();

    /**
     * unset when we leave the signed content
     */
    public void unsetIsInSignedContent();

    /**
     * @return true if we currently stay in signed content
     */
    public boolean isInSignedContent();
}
