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

package edu.internet2.middleware.shibboleth.idp.util;

import javax.servlet.http.HttpServletRequest;

/**
 * Helper class for dealing with HTTP related resoruces.
 */
public final class HttpHelper {
    
    /** Constructor. */
    private HttpHelper(){
        
    }

    /**
     * Gets the request URI as returned by {@link HttpServletRequest#getRequestURI()} but without the servlet context
     * path.
     * 
     * @param request request to get the URI from
     * 
     * @return constructed URI
     */
    public static String getRequestUriWithoutContext(HttpServletRequest request) {
        String servletPath = request.getServletPath();

        if (request.getPathInfo() == null) {
            return servletPath;
        } else {
            return servletPath + request.getPathInfo();
        }
    }
}