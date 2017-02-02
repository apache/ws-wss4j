/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.wss4j.common.ext;

import javax.security.auth.callback.Callback;
import java.util.List;

public class AttachmentRequestCallback implements Callback {

    private String attachmentId;
    private List<Attachment> attachments;
    private boolean removeAttachments = true;

    /**
     * The requested attachment which will be secured. If null all attachments are requested
     */
    public String getAttachmentId() {
        return attachmentId;
    }

    public void setAttachmentId(String attachmentId) {
        this.attachmentId = attachmentId;
    }

    public List<Attachment> getAttachments() {
        return attachments;
    }

    public void setAttachments(List<Attachment> attachments) {
        this.attachments = attachments;
    }

    public boolean isRemoveAttachments() {
        return removeAttachments;
    }

    /**
     * Set whether to remove the attachments when we're reading them. 
     * The default is "true".
     */
    public void setRemoveAttachments(boolean removeAttachments) {
        this.removeAttachments = removeAttachments;
    }
}
