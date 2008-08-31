/*
 * Copyright 2008 University Corporation for Advanced Internet Development, Inc.
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

package edu.internet2.middleware.shibboleth.idp.authn;

import java.security.Principal;

import org.opensaml.xml.util.DatatypeHelper;

/** A basic implementation of {@link Principal}. */
public class UsernamePrincipal implements Principal {

    /** Name of the principal. */
    private String name;

    /**
     * Constructor.
     * 
     * @param principalName name of the principal
     */
    public UsernamePrincipal(String principalName) {
        name = DatatypeHelper.safeTrimOrNullString(principalName);
    }

    /** {@inheritDoc} */
    public String getName() {
        return name;
    }

    /** {@inheritDoc} */
    public String toString() {
        return "{BasicPrincipal}" + getName();
    }

    /** {@inheritDoc} */
    public int hashCode() {
        return name.hashCode();
    }

    /** {@inheritDoc} */
    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }

        if (obj instanceof UsernamePrincipal) {
            return DatatypeHelper.safeEquals(getName(), ((UsernamePrincipal) obj).getName());
        }

        return false;
    }
}