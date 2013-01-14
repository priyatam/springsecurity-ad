package github.priyatam.springsecurity.spring;

import github.priyatam.springsecurity.domain.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import java.util.Collection;

/**
 * An implementation of Spring Security's UserDetailsService.
 */
public class AccountDetailsServiceImpl implements UserDetailsService {

    Logger logger = LoggerFactory.getLogger(AccountDetailsServiceImpl.class);

    @PersistenceContext
    private EntityManager entityManager;

    /**
     * Retrieve an account depending on its login this method is not case sensitive.<br>
     * use <code>obtainAccount</code> to match the login to either email, login or whatever is your login logic
     *
     * @param login the account login
     * @return a Spring Security userdetails object that matches the login
     * @throws UsernameNotFoundException when the user could not be found
     * @throws DataAccessException       when an error occured while retrieving the account
     * @see #obtainAccount(String)
     */
    @Transactional
    public UserDetails loadUserByUsername(String login) throws UsernameNotFoundException, DataAccessException {
        if (login == null || login.trim().isEmpty()) {
            throw new UsernameNotFoundException("Empty login");
        }

        logger.debug("Security verification for user '" + login + "'");

        User account = obtainAccount(login);

        if (account == null) {
            logger.info("Account " + login + " could not be found");
            throw new UsernameNotFoundException("account " + login + " could not be found");
        }

        Collection<GrantedAuthority> grantedAuthorities = obtainGrantedAuthorities(login);

        if (grantedAuthorities == null) {
            grantedAuthorities = github.priyatam.springsecurity.spring.SpringSecurityContext.toGrantedAuthorities(account.getRoleNames());
        }

        String password = obtainPassword(login);

        if (password == null) {
            password = account.getPassword();
        }

        boolean enabled = true;
        boolean accountNonExpired = true;
        boolean credentialsNonExpired = true;
        boolean accountNonLocked = true;

        return new org.springframework.security.core.userdetails.User(login, password, enabled, accountNonExpired,
                credentialsNonExpired, accountNonLocked, grantedAuthorities);
    }

    /**
     * Return the account depending on the login provided by spring security.
     *
     * @return the user if found
     */
    protected User obtainAccount(String username) {
        return entityManager.createNamedQuery("User.FIND_BY_USERNAME", User.class)
                .setParameter("username", username)
                .getSingleResult();
    }

    /**
     * Returns null. Subclass may override it to provide their own granted authorities.
     */
    protected Collection<GrantedAuthority> obtainGrantedAuthorities(String username) {
        return null;
    }

    /**
     * Returns null. Subclass may override it to provide their own password.
     */
    protected String obtainPassword(String username) {
        return null;
    }
}
