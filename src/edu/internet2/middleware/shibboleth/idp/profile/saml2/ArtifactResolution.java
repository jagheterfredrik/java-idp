/*
 * Copyright [2006] [University Corporation for Advanced Internet Development, Inc.]
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package edu.internet2.middleware.shibboleth.idp.profile.saml2;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.opensaml.common.binding.decoding.MessageDecoder;
import org.opensaml.common.binding.encoding.MessageEncoder;

import edu.internet2.middleware.shibboleth.common.profile.ProfileException;
import edu.internet2.middleware.shibboleth.common.profile.ProfileRequest;
import edu.internet2.middleware.shibboleth.common.profile.ProfileResponse;

/**
 * SAML 2.0 Artifact resolution profile handler.
 */
public class ArtifactResolution extends AbstractSAML2ProfileHandler {

    /** {@inheritDoc} */
    protected MessageDecoder<ServletRequest> getMessageDecoder(ProfileRequest<ServletRequest> request) throws ProfileException {
        // TODO Auto-generated method stub
        return null;
    }

    /** {@inheritDoc} */
    protected MessageEncoder<ServletResponse> getMessageEncoder(ProfileResponse<ServletResponse> response) throws ProfileException {
        // TODO Auto-generated method stub
        return null;
    }

    /** {@inheritDoc} */
    protected String getUserSessionId(ProfileRequest<ServletRequest> request) {
        // TODO Auto-generated method stub
        return null;
    }

    /** {@inheritDoc} */
    public void processRequest(ProfileRequest<ServletRequest> request, ProfileResponse<ServletResponse> response) throws ProfileException {
        // TODO Auto-generated method stub
        
    }
}