package github.priyatam.springsecurity.domain;

import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Convenience class to set and/or retrieve from the current thread of execution account information such as
 * <ul>
 * <li>User</li>
 * <li>username</li>
 * <li>associated role names</li>
 * <li>locale used</li>
 * </ul>
 * <p/>
 * Usually, you set this information as soon as it becomes available (e.g. in a servlet filter) so
 * you can access it during almost the entire lifecycle of an http-request.
 * <p/>
 * As data are stored in InheritableThreadLocal this method can be used also in spawn threads
 */
public class AccountContext {

    public static final String USER_SYSTEM = "system!";

    private static final ThreadLocal<AccountContext> accountContextHolder = new InheritableThreadLocal<AccountContext>();

    private String sessionId;
    private String username;
    private List<String> roles;
    private User account;

    /**
     * Bind the passed account context to the current thread.
     *
     * @param accountContext the current AccountContext to bind, or <code>null</code> to reset the thread-bound AccountContext.
     */
    public static void setAccountContext(AccountContext accountContext) {
        accountContextHolder.set(accountContext);
    }

    /**
     * Return the current account context bound to the current thread or <code>null</code> if no context is present.
     */
    public static AccountContext getAccountContext() {
        return accountContextHolder.get();
    }

    /**
     * Reset the account context bound to the current thread.
     */
    public static void resetAccountContext() {
        accountContextHolder.set(null);
    }

    public void setSessionId(String sessionId) {
        this.sessionId = sessionId;
    }

    /**
     * Return the current http session id.
     */
    public String getSessionId() {
        return sessionId;
    }

    /**
     * Bind the passed username to the account Context thread. This username is not set on the account.
     */
    public void setUsername(String username) {
        this.username = username;
    }

    /**
     * Return the username bound to the current context, if any.
     *
     * @return the current username, or <code>null</code> if none.
     */
    public String getUsername() {
        return username;
    }

    /**
     * Bind the passed roles to the current thread. These roles are not set on the account.
     *
     * @param roles the current user's roles, or <code>null</code> to reset the thread-bound roles collection.
     */
    public void setRoles(List<String> roles) {
        this.roles = roles;
    }

    /**
     * Return the roles associated with the current thread.
     *
     * @return the current roles, or an empty collection if none.
     */
    public List<String> getRoleNames() {
        if (roles != null) {
            return roles;
        }

        return new ArrayList<String>(0);
    }

    /**
     * Tell whether the passed role is set?
     *
     * @return true if the passed role is present, false otherwise.
     */
    public boolean hasRole(String roleName) {
        List<String> roles = getRoleNames();
        for (String role : roles) {
            if (role.equalsIgnoreCase(roleName)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Tell whether all the passed roles are set?
     *
     * @return true if all the passed roles are present, false otherwise.
     */
    public boolean hasAllRoles(String[] roleNames) {
        for (String roleName : roleNames) {
            if (!hasRole(roleName)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Tell whether at least one of the passed roles is set?
     *
     * @return true at least one of the passed roles is present, false otherwise
     */
    public boolean hasAnyRole(String[] roleNames) {
        for (String roleName : roleNames) {
            if (hasRole(roleName)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Tell whether all the passed roles are NOT set?
     *
     * @return true if none of the passed roles is present, false otherwise
     */
    public boolean hasNoRole(String[] roleNames) {
        for (String roleName : roleNames) {
            if (hasRole(roleName)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Bind the passed account to this account context.
     */
    public void setAccount(User account) {
        this.account = account;
    }

    /**
     * Return the User instance bound to the current thread, if any.
     *
     * @return the current account, or <code>null</code> if none.
     */
    public User getAccount() {
        return account;
    }

    /**
     * Tell whether the passed account is the same as the User
     * instance bound to the current thread, that is if their ids are equals.
     * It can be used for security purposes.
     *
     * @return true if the account primary keys are equal, false otherwise.
     */
    public boolean isAccount(User accountToCheck) {
        if (account != null && account.getId() != null && accountToCheck != null) {
            return account.getId().equals(accountToCheck.getId());
        }

        return false;
    }

    public static String getCurrentUsername() {
        String ret = null;
        AccountContext ac = AccountContext.getAccountContext();
        if (ac != null) {
            ret = ac.getUsername();
        }
        return StringUtils.hasText(ret) ? ret : USER_SYSTEM;
    }

    public static List<String> getCurrentUserRoles() {
        List<String> ret = null;
        AccountContext ac = AccountContext.getAccountContext();
        if (ac != null) {
            ret = ac.getRoleNames();
        }
        return ret == null ? java.util.Collections.<String>emptyList() : ret;
    }
}