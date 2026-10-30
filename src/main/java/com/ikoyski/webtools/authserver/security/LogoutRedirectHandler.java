package com.ikoyski.webtools.authserver.security;

import java.io.IOException;
import java.util.List;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.stereotype.Component;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * After /logout, sends the browser back to the app that asked, but only to an exact URL on the allow-list
 * (auth.logout.allowed-redirects). Anything else shows a plain "signed out" page, so this cannot be used
 * as an open redirect.
 */
@Component
public class LogoutRedirectHandler implements LogoutSuccessHandler {

    private final List<String> allowedRedirects;

    public LogoutRedirectHandler(@Value("${auth.logout.allowed-redirects:}") List<String> allowedRedirects) {
        this.allowedRedirects = allowedRedirects.stream().map(String::trim).filter(v -> !v.isEmpty()).toList();
    }

    @Override
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response,
                                Authentication authentication) throws IOException {
        String redirect = request.getParameter("redirect");
        if (redirect != null && allowedRedirects.contains(redirect)) {
            response.sendRedirect(redirect);
            return;
        }
        response.setContentType("text/html;charset=UTF-8");
        response.getWriter().write("<!doctype html><html><head><meta charset=\"utf-8\"><title>Signed out</title></head>"
                + "<body style=\"font-family:sans-serif;max-width:32rem;margin:4rem auto;padding:0 1rem\">"
                + "<h1>Signed out</h1><p>You have been signed out.</p></body></html>");
    }
}
