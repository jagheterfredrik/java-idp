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

package edu.internet2.middleware.shibboleth.idp.session.impl;

import java.net.InetAddress;

import org.joda.time.DateTime;
import org.opensaml.util.storage.ExpiringObject;
import org.opensaml.util.storage.StorageService;
import org.opensaml.xml.util.DatatypeHelper;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;

import edu.internet2.middleware.shibboleth.common.session.LoginEvent;
import edu.internet2.middleware.shibboleth.common.session.LogoutEvent;
import edu.internet2.middleware.shibboleth.common.session.SessionManager;
import edu.internet2.middleware.shibboleth.idp.session.Session;

/**
 * Manager of IdP sessions.
 */
public class SessionManagerImpl implements SessionManager<Session>, ApplicationContextAware {

    /** Spring context used to publish login and logout events. */
    private ApplicationContext appCtx;
    
    /** Backing service used to store sessions. */
    private StorageService<String, SessionManagerEntry> sessionStore;
    
    /** Parition in which entries are stored. */
    private String partition;
    
    /** Lifetime, in milliseconds, of session. */
    private long sessionLifetime;
    
    /**
     * Constructor.
     *
     * @param storageService service used to store sessions
     * @param lifetime lifetime, in milliseconds, of sessions
     */
    public SessionManagerImpl(StorageService<String, SessionManagerEntry> storageService, long lifetime){
        sessionStore = storageService;
        partition = "session";
        sessionLifetime = lifetime;
    }
    
    /**
     * Constructor.
     *
     * @param storageService service used to store session
     * @param storageParition partition in which sessions are stored
     * @param lifetime lifetime, in milliseconds, of sessions
     */
    public SessionManagerImpl(StorageService<String, SessionManagerEntry> storageService, String storageParition, long lifetime){
        sessionStore = storageService;
        if(!DatatypeHelper.isEmpty(storageParition)){
            partition = DatatypeHelper.safeTrim(storageParition);
        }else{
            partition = "session";
        }
        sessionLifetime = lifetime;
    }
    
    /** {@inheritDoc} */
    public void setApplicationContext(ApplicationContext applicationContext) {
        appCtx = applicationContext;
    }
    
    /** {@inheritDoc} */
    public Session createSession(InetAddress presenter, String principal) {
        Session session = new SessionImpl(presenter, principal);
        SessionManagerEntry sessionEntry = new SessionManagerEntry(this, session, sessionLifetime);
        sessionStore.put(partition, session.getSessionID(), sessionEntry);
        appCtx.publishEvent(new LoginEvent(session));
        return session;
    }

    /** {@inheritDoc} */
    public void destroySession(String sessionID) {
        SessionManagerEntry sessionEntry = sessionStore.get(partition, sessionID);
        if(sessionEntry != null){
            appCtx.publishEvent(new LogoutEvent(sessionEntry.getSession()));
        }
    }

    /** {@inheritDoc} */
    public Session getSession(String sessionID) {
        SessionManagerEntry sessionEntry = sessionStore.get(partition, sessionID); 
        if(sessionEntry.isExpired()){
            destroySession(sessionEntry.getSessionId());
            return null;
        }else{
            return sessionEntry.getSession();
        }
    }
    
    /**
     * Session store entry.
     */
    public class SessionManagerEntry implements ExpiringObject {
        
        /** User's session. */
        private Session userSession;
        
        /** Manager that owns the session. */
        private SessionManager<Session> sessionManager;
        
        /** Time this entry expires. */
        private DateTime expirationTime;
        
        /**
         * Constructor.
         *
         * @param manager manager that owns the session
         * @param session user session
         * @param sessionLifetime lifetime of session
         */
        public SessionManagerEntry(SessionManager<Session> manager, Session session, long sessionLifetime){
            sessionManager = manager;
            userSession = session;
            expirationTime = new DateTime().plus(sessionLifetime);
        }
        
        /**
         * Gets the user session.
         * 
         * @return user session
         */
        public Session getSession(){
            return userSession;
        }
        
        /**
         * Gets the ID of the user session.
         * 
         * @return ID of the user session
         */
        public String getSessionId(){
            return userSession.getSessionID();
        }

        /** {@inheritDoc} */
        public DateTime getExpirationTime() {
            return expirationTime;
        }

        /** {@inheritDoc} */
        public boolean isExpired() {
            return expirationTime.isBeforeNow();
        }
        
        /** {@inheritDoc} */
        public void onExpire() {
            sessionManager.destroySession(userSession.getSessionID());
        }
    }
}