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
package ch.gigerstyle.xmlsec.impl;

import ch.gigerstyle.xmlsec.ext.Constants;
import ch.gigerstyle.xmlsec.ext.DocumentContext;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamConstants;
import java.util.ArrayList;
import java.util.List;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class DocumentContextImpl implements DocumentContext {

    private static final QName nullElement = new QName("", "");
    private List<QName> path = new ArrayList<QName>(10);
    private String encoding;

    public String getEncoding() {
        return encoding;
    }

    public void setEncoding(String encoding) {
        this.encoding = encoding;
    }

    public void addPathElement(QName qName) {
        path.add(qName);
    }

    public QName removePathElement() {
        return path.remove(path.size() - 1);
    }

    protected void setPath(List<QName> path) {
        this.path = path;
    }

    public List<QName> getPath() {
        return path;
    }

    public QName getParentElement(int eventType) {
        if (eventType == XMLStreamConstants.START_ELEMENT || eventType == XMLStreamConstants.END_ELEMENT) {
            if (path.size() >= 2) {
                return path.get(path.size() - 2);
            } else {
                return nullElement;
            }
        } else {
            if (path.size() >= 1) {
                return path.get(path.size() - 1);
            } else {
                return nullElement;
            }
        }
    }

    public boolean isInSOAPHeader() {
        return (path.size() > 1 && path.get(1).equals(Constants.TAG_soap11_Header));
    }

    public boolean isInSOAPBody() {
        return (path.size() > 1 && path.get(1).equals(Constants.TAG_soap11_Body));
    }

    public int getDocumentLevel() {
        return path.size();
    }

    private boolean inSecurityHeader = false;

    public boolean isInSecurityHeader() {
        return inSecurityHeader;
    }

    public void setInSecurityHeader(boolean inSecurityHeader) {
        this.inSecurityHeader = inSecurityHeader;
    }

    private int actualEncryptedContentCounter = 0;

    public synchronized void setIsInEncryptedContent() {
        this.actualEncryptedContentCounter++;
    }

    public synchronized void unsetIsInEncryptedContent() {
        this.actualEncryptedContentCounter--;
    }

    public boolean isInEncryptedContent() {
        return this.actualEncryptedContentCounter > 0;
    }

    private int actualSignedContentCounter = 0;

    public synchronized void setIsInSignedContent() {
        this.actualSignedContentCounter++;
    }

    public synchronized void unsetIsInSignedContent() {
        this.actualSignedContentCounter--;
    }

    public boolean isInSignedContent() {
        return this.actualSignedContentCounter > 0;
    }

    @Override
    protected DocumentContextImpl clone() {
        DocumentContextImpl documentContext = new DocumentContextImpl();
        List<QName> subPath = new ArrayList<QName>();
        subPath.addAll(this.path);
        documentContext.setEncoding(this.encoding);
        documentContext.setPath(subPath);
        documentContext.setInSecurityHeader(isInSecurityHeader());
        documentContext.actualEncryptedContentCounter = this.actualEncryptedContentCounter;
        documentContext.actualSignedContentCounter = this.actualSignedContentCounter;
        return documentContext;
    }
}
