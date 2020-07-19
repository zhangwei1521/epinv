package com.zhangwei.epinv.jwt;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.pam.AuthenticationStrategy;
import org.apache.shiro.authc.pam.ModularRealmAuthenticator;
import org.apache.shiro.authc.pam.ShortCircuitIterationException;
import org.apache.shiro.realm.Realm;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collection;

public class MultiRealmAuthenticator extends ModularRealmAuthenticator {

    private static final Logger log = LoggerFactory.getLogger(MultiRealmAuthenticator.class);

    @Override
    protected AuthenticationInfo doMultiRealmAuthentication(Collection<Realm> realms, AuthenticationToken token) {
        AuthenticationStrategy strategy = getAuthenticationStrategy();

        AuthenticationInfo aggregate = strategy.beforeAllAttempts(realms, token);

        if (log.isTraceEnabled()) {
            log.trace("Iterating through {} realms for PAM authentication", realms.size());
        }
        AuthenticationException authenticationException = null;
        for (Realm realm : realms) {

            try {
                aggregate = strategy.beforeAttempt(realm, token, aggregate);
            } catch (ShortCircuitIterationException shortCircuitSignal) {
                // Break from continuing with subsequnet realms on receiving
                // short circuit signal from strategy
                break;
            }

            if (realm.supports(token)) {

                log.trace("Attempting to authenticate token [{}] using realm [{}]", token, realm);

                AuthenticationInfo info = null;

                try {
                    info = realm.getAuthenticationInfo(token);
                } catch (AuthenticationException e) {
                    authenticationException = e;
                    if (log.isDebugEnabled()) {
                        String msg = "Realm [" + realm + "] threw an exception during a multi-realm authentication attempt:";
                        log.debug(msg, authenticationException);
                    }
                }

                aggregate = strategy.afterAttempt(realm, token, info, aggregate, authenticationException);

            } else {
                log.debug("Realm [{}] does not support token {}.  Skipping realm.", realm, token);
            }
        }
        if(authenticationException != null){
            throw authenticationException;
        }

        aggregate = strategy.afterAllAttempts(token, aggregate);

        return aggregate;
    }
}
