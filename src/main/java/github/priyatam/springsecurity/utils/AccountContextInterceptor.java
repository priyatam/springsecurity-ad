package github.priyatam.springsecurity.utils;

import github.priyatam.springsecurity.domain.AccountContext;
import github.priyatam.springsecurity.domain.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * This interceptor is responsible for setting up the accountContext on the current thread of
 * execution and pass it to the view using the ModelMap.
 */
@Service
public class AccountContextInterceptor implements HandlerInterceptor {

    @Autowired
    private github.priyatam.springsecurity.utils.AccountContextSupport accountContextSupport;

    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
            throws ServletException {
        // Setup AccountContext and Log Context
        accountContextSupport.processAccountContext(request);
        User n = null;
        // Give access to the current account context to the view
        // Note: using the modelAndView in the postHandle would not work
        //       in view returned by Spring Web Flow
        request.setAttribute("accountContext", AccountContext.getAccountContext());

        // proceed
        return true;
    }

    public void postHandle(HttpServletRequest request, HttpServletResponse response, Object handler,
                           ModelAndView modelAndView) {
    }

    public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex)
            throws Exception {
        accountContextSupport.resetContext();
    }
}