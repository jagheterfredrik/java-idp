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

package edu.internet2.middleware.shibboleth.idp.session.impl;

import org.joda.time.DateTime;

import edu.internet2.middleware.shibboleth.idp.session.AuthenticationMethodInformation;
import edu.internet2.middleware.shibboleth.idp.session.ServiceInformation;

/**
 * Information about a service a user has logged in to.
 */
public class ServiceInformationImpl implements ServiceInformation {

    /** Entity ID of the service. */
    private String entityID;

    /** Instant the user was authenticated to the service. */
    private DateTime authenticationInstant;

    /** Authentication method used to authenticate the user to the service. */
    private AuthenticationMethodInformation methodInfo;

    /**
     * Default constructor.
     * 
     * @param id unique identifier for the service.
     * @param loginInstant time the user logged in to the service.
     * @param method authentication method used to log into the service.
     */
    public ServiceInformationImpl(String id, DateTime loginInstant, AuthenticationMethodInformation method) {
        entityID = id;
        authenticationInstant = loginInstant;
        methodInfo = method;
    }

    /** {@inheritDoc} */
    public String getEntityID() {
        return entityID;
    }

    /** {@inheritDoc} */
    public DateTime getLoginInstant() {
        return authenticationInstant;
    }

    /** {@inheritDoc} */
    public AuthenticationMethodInformation getAuthenticationMethod() {
        return methodInfo;
    }

    /** {@inheritDoc} */
    public int hashCode() {
        return entityID.hashCode();
    }

    /** {@inheritDoc} */
    public boolean equals(Object obj) {
        if(obj == this){
            return true;
        }
        
        if (!(obj instanceof ServiceInformation)) {
            return false;
        }

        ServiceInformation si = (ServiceInformation) obj;
        return entityID.equals(si.getEntityID());
    }
}