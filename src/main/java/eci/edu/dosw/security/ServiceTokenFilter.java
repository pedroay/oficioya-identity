package eci.edu.dosw.security;

import eci.edu.dosw.identity.service.JwtProvider;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

/**
 * Autentica únicamente el token de servicio del orquestador: firma y vigencia válidas,
 * subject del servicio y rol SERVICE. Cualquier otro token se ignora (la petición queda
 * sin autenticar y el entry point responde 401).
 */
// Sin @Component: se registra solo dentro de la cadena de seguridad.
public class ServiceTokenFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(ServiceTokenFilter.class);
    private static final String PREFIX = "Bearer ";
    private static final String SERVICE_ROLE = "SERVICE";

    private final JwtProvider jwtProvider;

    public ServiceTokenFilter(JwtProvider jwtProvider) {
        this.jwtProvider = jwtProvider;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
            FilterChain chain) throws ServletException, IOException {
        String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (header != null && header.startsWith(PREFIX)) {
            autenticar(header.substring(PREFIX.length()).trim());
        }
        chain.doFilter(request, response);
    }

    private void autenticar(String token) {
        try {
            Claims claims = jwtProvider.parse(token);
            if (!JwtProvider.SERVICE_SUBJECT.equals(claims.getSubject()) || !tieneRolServicio(claims)) {
                log.debug("Token rechazado: no es un token de servicio");
                return;
            }
            SecurityContextHolder.getContext().setAuthentication(
                    new UsernamePasswordAuthenticationToken(claims.getSubject(), null,
                            List.of(new SimpleGrantedAuthority("ROLE_" + SERVICE_ROLE))));
        } catch (JwtException | IllegalArgumentException e) {
            log.debug("Token rechazado: {}", e.getClass().getSimpleName());
        }
    }

    private boolean tieneRolServicio(Claims claims) {
        List<?> roles = claims.get("roles", List.class);
        return roles != null && roles.stream().map(String::valueOf).anyMatch(SERVICE_ROLE::equals);
    }
}