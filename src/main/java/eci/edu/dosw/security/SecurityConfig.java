package eci.edu.dosw.security;

import eci.edu.dosw.identity.service.JwtProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * Identity no es público: solo el orquestador (rol SERVICE) puede usar /internal/**.
 * Todo lo demás se deniega.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http, JwtProvider jwtProvider,
            RestAuthenticationEntryPoint entryPoint,
            RestAccessDeniedHandler deniedHandler) throws Exception {
        http.csrf(csrf -> csrf.disable())
            .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .httpBasic(b -> b.disable())
            .formLogin(f -> f.disable())
            .exceptionHandling(e -> e
                .authenticationEntryPoint(entryPoint)
                .accessDeniedHandler(deniedHandler))
            .authorizeHttpRequests(a -> a
                .requestMatchers("/error").permitAll()
                .requestMatchers("/internal/**").hasRole("SERVICE")
                .anyRequest().denyAll())
            .addFilterBefore(new ServiceTokenFilter(jwtProvider),
                UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }
}