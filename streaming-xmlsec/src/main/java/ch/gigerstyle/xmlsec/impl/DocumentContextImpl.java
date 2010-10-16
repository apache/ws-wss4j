package ch.gigerstyle.xmlsec.impl;

import ch.gigerstyle.xmlsec.ext.Constants;
import ch.gigerstyle.xmlsec.ext.DocumentContext;
import ch.gigerstyle.xmlsec.impl.util.FiFoQueue;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamConstants;
import java.util.ArrayList;
import java.util.List;

/**
 * User: giger
 * Date: Oct 13, 2010
 * Time: 8:09:33 PM
 * Copyright 2010 Marc Giger gigerstyle@gmx.ch
 * <p/>
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 * <p/>
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * <p/>
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */
public class DocumentContextImpl implements DocumentContext {

    private static final QName nullElement = new QName("", "");

    private List<QName> path = new ArrayList<QName>(10);

    protected void addPathElement(QName qName) {
        path.add(qName);
    }

    protected QName removePathElement() {
        return path.remove(path.size() - 1);
    }

    protected void setPath(List<QName> path) {
        this.path = path;
    }

    public List<QName> getPath() {
        return path;
    }

    public QName getParentElement(int eventType) {
        if (eventType == XMLStreamConstants.START_ELEMENT) {
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

    @Override
    protected DocumentContextImpl clone() {
        DocumentContextImpl documentContext = new DocumentContextImpl();
        List<QName> subPath = new ArrayList<QName>();
        subPath.addAll(path);
        documentContext.setPath(subPath);
        return documentContext; 
    }
}
