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
package org.swssf.ext;

/**
 * Exception when configuration errors are detected
 *
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class WSSConfigurationException extends WSSecurityException {

    public WSSConfigurationException(ErrorCode errorCode, String msgId, Object[] args, Throwable exception) {
        super(errorCode, msgId, exception, args);
    }

    public WSSConfigurationException(ErrorCode errorCode, String msgId, Throwable exception) {
        super(errorCode, msgId, exception);
    }

    public WSSConfigurationException(ErrorCode errorCode, String msgId, Object[] args) {
        super(errorCode, msgId, args);
    }

    public WSSConfigurationException(ErrorCode errorCode, String msgId) {
        super(errorCode, msgId);
    }

    public WSSConfigurationException(ErrorCode errorCode) {
        super(errorCode);
    }

    public WSSConfigurationException(String errorMessage) {
        super(errorMessage);
    }

    public WSSConfigurationException(String errorMessage, Throwable t) {
        super(errorMessage, t);
    }
}
