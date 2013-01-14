package github.priyatam.springsecurity.spring;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.GrantedAuthorityImpl;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * Get Spring security context to access user data security infos
 */
public abstract class SpringSecurityContext {
    static Logger logger = LoggerFactory.getLogger(SpringSecurityContext.class);

    /**
     * Get the current username. Note that it may not correspond to a username that
     * currently exists in your accounts' repository; it could be a spring security
     * 'anonymous user'.
     *
     * @return the current user's username, or null if none.
     */
    public static String getUsername() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        if (auth != null) {
            Object principal = auth.getPrincipal();

            if (principal instanceof UserDetails) {
                return ((UserDetails) principal).getUsername();
            }

            return (String) principal.toString();
        }

        return null;
    }

    /**
     * Retrieve the current UserDetails bound to the current thread by Spring Security, if any.
     */
    public static UserDetails getUserDetails() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        if (auth != null && auth.getPrincipal() instanceof UserDetails) {
            return ((UserDetails) auth.getPrincipal());
        }

        return null;
    }

    /**
     * Return the current roles bound to the current thread by Spring Security.
     */
    public static List<String> getRoles() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        if (auth != null) {
            return toStringList(auth.getAuthorities());
        }

        return new ArrayList<String>(0);
    }

    /**
     * Force user authentication programmatically. It can be used to auto login a user
     * upon a successful registration phase, when the user confirms his email
     * address for example. Do not overuse it
     *
     * @param login
     * @param password
     * @param grantedRoles the roles granted to the user.
     */
    public static void forceAuthentication(String login, String password, List<String> grantedRoles) {
        logger.debug("Forcing authentication for login: " + login);

        Collection<GrantedAuthority> roles = toGrantedAuthorities(grantedRoles);
        boolean enabled = true;
        boolean accountNonExpired = true;
        boolean credentialsNonExpired = true;
        boolean accountNonLocked = true;

        User user = new User(login, password, enabled, accountNonExpired, credentialsNonExpired, accountNonLocked,
                roles);
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken(user, password, roles));
    }

    public static Collection<GrantedAuthority> toGrantedAuthorities(List<String> roles) {
        List<GrantedAuthority> result = new ArrayList<GrantedAuthority>();

        for (String role : roles) {
            result.add(new GrantedAuthorityImpl(role));
        }

        return result;
    }

    public static List<String> toStringList(Iterable<GrantedAuthority> grantedAuthorities) {
        List<String> result = new ArrayList<String>();

        for (GrantedAuthority grantedAuthority : grantedAuthorities) {
            result.add(grantedAuthority.getAuthority());
        }

        return result;
    }
}
