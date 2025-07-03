package com.LinkedInClone.LinkedInClone.features.Authentication.Filter;

import com.LinkedInClone.LinkedInClone.features.Authentication.Model.AuthenticationUser;
import com.LinkedInClone.LinkedInClone.features.Authentication.Service.AuthenticationService;
import com.LinkedInClone.LinkedInClone.features.Authentication.Utils.JsonWebToken;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpFilter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

@Component
public class AuthenticationFilter extends HttpFilter {
    private final List<String> unsecuredEndPoints = Arrays.asList(
            "/api/v1/auth/login",
            "/api/v1/auth/register",
            "/api/v1/auth/send-password-reset-token",
            "/api/v1/auth/reset-password"
    );

    private final JsonWebToken jsonWebToken;
    private final AuthenticationService authenticationService;

    public AuthenticationFilter(JsonWebToken jsonWebToken, AuthenticationService authenticationService) {
        this.jsonWebToken = jsonWebToken;
        this.authenticationService = authenticationService;
    }

    @Override
    protected void doFilter(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filter) throws IOException, ServletException{
        httpServletResponse.addHeader("Access-Control-Allow-Origin","*");
        httpServletResponse.addHeader("Access-Control-Allow-Methods","GET,POST,PUT,DELETE,OPTIONS");
        httpServletResponse.addHeader("Access-Control-Allow-Headers","Content-Type,Authorization");

        if("OPTIONS".equalsIgnoreCase(httpServletRequest.getMethod()))
        {
            httpServletResponse.setStatus(HttpServletResponse.SC_OK);
            return;
        }

        if(unsecuredEndPoints.contains(httpServletRequest.getRequestURI())){
            filter.doFilter(httpServletRequest,httpServletResponse);
            return;
        }

        try{
            String authorization = httpServletRequest.getHeader("Authorization");

            if(authorization == null || !authorization.startsWith("Bearer "))
            {
                throw new ServletException("token missing");
            }

            String token = authorization.substring(7);

            if(jsonWebToken.isTokenExpired(token))
            {
                throw new ServletException("invalid token");
            }

            String email = jsonWebToken.getEmailFromToken(token);
            AuthenticationUser user = authenticationService.getUser(email);
            httpServletRequest.setAttribute("authenticatedUser",user);
            filter.doFilter(httpServletRequest,httpServletResponse);
        }
        catch(Exception e)
        {
            httpServletResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            httpServletResponse.setContentType("application/json");
            httpServletResponse.getWriter().write("{\"message\": \"invalid authentication token,or token missing\"}");
        }
    }
}
