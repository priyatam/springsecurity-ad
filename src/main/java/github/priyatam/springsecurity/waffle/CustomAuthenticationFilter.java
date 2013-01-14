package github.priyatam.springsecurity.waffle;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.context.SecurityContextHolder;
import waffle.servlet.WindowsPrincipal;
import waffle.spring.NegotiateSecurityFilter;
import waffle.util.AuthorizationHeader;
import waffle.windows.auth.IWindowsIdentity;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Custom Authentication Filter extending Waffle's built-in Filter.
 * Loads User Roles from Db
 */
public class CustomAuthenticationFilter extends NegotiateSecurityFilter {

    Logger logger = LoggerFactory.getLogger(CustomAuthenticationFilter.class);

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;

        logger.info(request.getMethod() + " " + request.getRequestURI() + ", contentlength: " + request.getContentLength());
        AuthorizationHeader authorizationHeader = new AuthorizationHeader(request);

        // authenticate user
        if (!authorizationHeader.isNull()
                && getProvider().isSecurityPackageSupported(authorizationHeader.getSecurityPackage())) {

            // log the user in using the token
            IWindowsIdentity windowsIdentity = null;

            try {
                windowsIdentity = getProvider().doFilter(request, response);
                if (windowsIdentity == null) {
                    return;
                }
            } catch (Exception e) {
                logger.warn("error logging in user: " + e.getMessage());
                sendUnauthorized(response, true);
                return;
            }

            if (!getAllowGuestLogin() && windowsIdentity.isGuest()) {
                logger.warn("guest login disabled: " + windowsIdentity.getFqn());
                sendUnauthorized(response, true);
                return;
            }

            try {
                logger.debug("logged in user: " + windowsIdentity.getFqn() +
                        " (" + windowsIdentity.getSidString() + ")");
                WindowsPrincipal principal = new WindowsPrincipal(
                        windowsIdentity, getPrincipalFormat(), getRoleFormat());
                logger.debug("roles: " + principal.getRolesString());

                // Populate Authentication Token along with GrantedAuthorities
                CustomAuthenticationToken authentication = new CustomAuthenticationToken(principal);

                SecurityContextHolder.getContext().setAuthentication(authentication);
                logger.info("successfully logged in user: " + windowsIdentity.getFqn());
            } finally {
                windowsIdentity.dispose();
            }
        }

        chain.doFilter(request, response);
    }

    /**
     * Send a 401 Unauthorized along with protocol authentication headers.
     *
     * @param response HTTP Response
     * @param close    Close connection.
     */
    private void sendUnauthorized(HttpServletResponse response, boolean close) {
        try {
            getProvider().sendUnauthorized(response);
            if (close) {
                response.setHeader("Connection", "close");
            } else {
                response.setHeader("Connection", "keep-alive");
            }
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
            response.flushBuffer();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
