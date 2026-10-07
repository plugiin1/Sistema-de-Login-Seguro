package com.pfc.auth.config;

import com.pfc.auth.entity.Role;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    private static final String[] ROTAS_PUBLICAS = {
        "/login", "/cadastro", "/acesso-negado", "/error",
        "/css/**", "/js/**", "/images/**", "/themes/**", "/favicon.ico"
    };

    private static final String[] ROTAS_ADMIN = {
        "/admin/**",
        "/ajustes-horarios/**", "/api/ajustes-horarios/**",
        "/tecnicos/**", "/tipo-chamado/**", "/recursos/**"
    };

    private static final String[] ROTAS_EQUIPE = {
        "/clientes/**", "/api/clientes/**"
    };

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers(ROTAS_PUBLICAS).permitAll()
                .requestMatchers(ROTAS_ADMIN).hasRole(Role.ADMIN.name())
                .requestMatchers(ROTAS_EQUIPE).hasAnyRole(Role.ADMIN.name(), Role.TECNICO.name())
                .anyRequest().authenticated()
            )
            .formLogin(form -> form
                .loginPage("/login")
                .defaultSuccessUrl("/", true)
                .failureUrl("/login?error")
                .permitAll()
            )
            .logout(logout -> logout
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login?logout")
                .invalidateHttpSession(true)
                .clearAuthentication(true)
                .deleteCookies("JSESSIONID", "SESSION")
            )
            .exceptionHandling(ex -> ex
                .accessDeniedPage("/acesso-negado")
            )
            .sessionManagement(session -> session
                .sessionFixation(fixation -> fixation.changeSessionId())
            );
        return http.build();
    }
}
