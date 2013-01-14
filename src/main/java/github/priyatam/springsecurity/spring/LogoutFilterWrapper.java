package github.priyatam.springsecurity.pojo;

import github.priyatam.springsecurity.domain.User;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;

import javax.annotation.PostConstruct;
import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Custom Logout Filter. Sets up urls for generic logout page and cases where it needs to be a custom
 * page (user inactivity, too many logins etc.,)
 */
public class LogoutFilterWrapper
        implements Filter {

    private String logoutSuccessfulUrl;

    private String logoutSuccessfulInactivityUrl;

    private LogoutFilter filter;

    @PostConstruct
    protected void initialize() {

        final SecurityContextLogoutHandler sclh = new SecurityContextLogoutHandler();
        sclh.setInvalidateHttpSession(true);
        this.filter =
                new LogoutFilter(new CustomLogoutSuccessHandler(), new LogoutHandler[]{sclh});
    }

    public void setLogoutSuccessfulUrl(String inUrl) {
        this.logoutSuccessfulUrl = inUrl;
    }

    public void setLogoutSuccessfulUrlInactivity(String inUrl) {
        this.logoutSuccessfulInactivityUrl = inUrl;
    }

    @Override
    public String toString() {
        return getClass().getName() + "{" + this.filter + "}";
    }

    public final void init(FilterConfig inFilterConfig) throws ServletException {
        this.filter.init(inFilterConfig);
    }

    public final void destroy() {
        this.filter.destroy();
    }

    public final void doFilter(ServletRequest inRequest, ServletResponse inResponse, FilterChain inChain)
            throws IOException, ServletException {
        this.filter.doFilter(inRequest, inResponse, inChain);
    }

    /**
     * Success Handler
     */
    private class CustomLogoutSuccessHandler implements LogoutSuccessHandler {

        private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

        @Override
        public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
                throws IOException, ServletException {

            String targetUrl = "";
            User principal = null;

            if (authentication != null) {
                if (!(authentication.getPrincipal() instanceof User)) {
                    throw new IllegalArgumentException("Invalid security principal type!");
                }
                principal = (User) authentication.getPrincipal();
            }

            if (principal == null) {
                throw new IllegalStateException("Security principal is not initialized!");
            }

            final String loginUrl = LogoutFilterWrapper.this.logoutSuccessfulUrl;

            final String timeoutUrl =
                    LogoutFilterWrapper.this.logoutSuccessfulInactivityUrl
                            + "?login="
                            + request.getContextPath()
                            + loginUrl;

            targetUrl = request.getQueryString().contains("timeout=true") ? timeoutUrl : loginUrl;

            redirectStrategy.sendRedirect(request, response, targetUrl);
        }
    }
}
