package github.priyatam.springsecurity.waffle;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import waffle.servlet.WindowsPrincipal;
import waffle.spring.GuestLoginDisabledAuthenticationException;
import waffle.spring.WindowsAuthenticationProvider;
import waffle.windows.auth.IWindowsIdentity;

/**
 * Custom Authentication Provider that extends Waffle Authentication Provider to add Roles
 * from SAEC Db
 */
public class CustomAuthenticationProvider extends WindowsAuthenticationProvider {

    Logger logger = LoggerFactory.getLogger(CustomAuthenticationProvider.class);

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        try {
            UsernamePasswordAuthenticationToken auth = (UsernamePasswordAuthenticationToken) authentication;
            IWindowsIdentity windowsIdentity = getAuthProvider().logonUser(auth.getName(), auth.getCredentials().toString());
            logger.debug("logged in user: " + windowsIdentity.getFqn() + " (" + windowsIdentity.getSidString() + ")");

            if (!getAllowGuestLogin() && windowsIdentity.isGuest()) {
                logger.warn("guest login disabled: " + windowsIdentity.getFqn());
                throw new GuestLoginDisabledAuthenticationException(windowsIdentity.getFqn());
            }

            WindowsPrincipal windowsPrincipal = new WindowsPrincipal(windowsIdentity, getPrincipalFormat(), getRoleFormat());
            logger.debug("roles: " + windowsPrincipal.getRolesString());

            // Populate Authentication Token along with GrantedAuthorities
            CustomAuthenticationToken token = new CustomAuthenticationToken(windowsPrincipal);
            logger.info("successfully logged in user: " + windowsIdentity.getFqn());
            return token;
        } catch (Exception e) {
            logger.error("An error occurred while loading Authentication Roles: " + e.getMessage());
            e.printStackTrace();
            throw new AuthenticationServiceException(e.getMessage(), e);
        }
    }

}
