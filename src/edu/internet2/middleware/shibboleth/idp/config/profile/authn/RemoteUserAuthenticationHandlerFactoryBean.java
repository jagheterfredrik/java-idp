/*
 * Copyright [2007] [University Corporation for Advanced Internet Development, Inc.]
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

package edu.internet2.middleware.shibboleth.idp.config.profile.authn;

import edu.internet2.middleware.shibboleth.idp.authn.provider.RemoteUserAuthenticationHandler;

/**
 * Spring factory for {@link RemoteUserAuthenticationHandler}.
 */
public class RemoteUserAuthenticationHandlerFactoryBean extends AbstractAuthenticationHandlerFactoryBean {

    /** Path to protected servlet. */
    private String protectedServletPath;

    /** {@inheritDoc} */
    public Class getObjectType() {
        return RemoteUserAuthenticationHandler.class;
    }

    /**
     * Gets the path to protected servlet.
     * 
     * @return path to protected servlet
     */
    public String getProtectedServletPath() {
        return protectedServletPath;
    }

    /**
     * Sets the path to protected servlet.
     * 
     * @param path Tpath to protected servlet
     */
    public void setProtectedServletPath(String path) {
        this.protectedServletPath = path;
    }

    /** {@inheritDoc} */
    protected Object createInstance() throws Exception {
        RemoteUserAuthenticationHandler handler = new RemoteUserAuthenticationHandler();
        handler.setServletURL(getProtectedServletPath());
        populateHandler(handler);
        return handler;
    }
}