package github.priyatam.springsecurity.utils;

import github.priyatam.springsecurity.domain.AccountContext;
import github.priyatam.springsecurity.domain.User;
import github.priyatam.springsecurity.spring.SpringSecurityContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.servlet.http.HttpServletRequest;

@Service
public class AccountContextSupport {
    static Logger logger = LoggerFactory.getLogger(AccountContextSupport.class);

    @PersistenceContext
    private EntityManager entityManager;
    
    /**
     * Set up the AccountContext on the current thread.
     * Should be invoked once, e.g from your web filter or interceptor.
     * Do not forget to call the resetContext method when you are done
     * with the request.
     */
    public void processAccountContext(HttpServletRequest req) {
        // set up the account context
        AccountContext accountContext = new AccountContext();
        AccountContext.setAccountContext(accountContext);
        accountContext.setSessionId(req.getSession().getId());
        accountContext.setRoles(SpringSecurityContext.getRoles());

        if (SpringSecurityContext.getUserDetails() != null) {
            // load the account from the database.
            // we assume here that the second level cache is used,
            // otherwise we would hit the database at each request.
            User account = obtainAccount(SpringSecurityContext.getUsername());

            if (account != null) {
                // set up account context for this thread
                accountContext.setAccount(account);
                accountContext.setUsername(account.getUsername());
            }
        } else if (logger.isDebugEnabled()) {
            logger.debug("No user details");
        }
    }

    /**
     * Reset the account context and the log context from the current thread.
     */
    public void resetContext() {
        AccountContext.resetAccountContext();
    }
    
    public User obtainAccount(String username) {
        return entityManager.createNamedQuery("User.FIND_BY_USERNAME", User.class)
                .setParameter("username", username)
                .getSingleResult();
    }
}