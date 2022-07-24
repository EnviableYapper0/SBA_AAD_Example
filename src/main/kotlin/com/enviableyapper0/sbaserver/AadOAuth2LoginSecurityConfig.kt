package com.enviableyapper0.sbaserver

import com.azure.spring.cloud.autoconfigure.aad.AadWebSecurityConfigurerAdapter
import de.codecentric.boot.admin.server.config.AdminServerProperties
import org.springframework.beans.factory.annotation.Value
import org.springframework.http.HttpMethod
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.crypto.factory.PasswordEncoderFactories
import org.springframework.security.web.csrf.CookieCsrfTokenRepository
import org.springframework.security.web.util.matcher.AntPathRequestMatcher


const val CLIENT_ROLE = "MONITOR"

@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
class AadOAuth2LoginSecurityConfig(
    val adminServer: AdminServerProperties,
    @Value("\${client.username}") val clientUsername: String,
    @Value("\${client.password}") val clientRawPassword: String
) : AadWebSecurityConfigurerAdapter() {

    override fun configure(http: HttpSecurity) {
        super.configure(http)

        val registerUrlPattern = "${adminServer.contextPath}/instances"
        val deleteUrlPattern = "$registerUrlPattern/*"

        http.authorizeRequests()
            .antMatchers(HttpMethod.POST, registerUrlPattern).hasRole(CLIENT_ROLE)
            .antMatchers(HttpMethod.DELETE, deleteUrlPattern).hasRole(CLIENT_ROLE)
            .anyRequest().authenticated()
            .and()
            .httpBasic()
            .and()
            .csrf()
            .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
            .ignoringRequestMatchers(
                AntPathRequestMatcher(registerUrlPattern, HttpMethod.POST.toString()),
                AntPathRequestMatcher(deleteUrlPattern, HttpMethod.DELETE.toString())
            )
    }

    /*
     * Manually insert username and password for use by sba client basic authentication. If one wants to have multiple
     * credentials for use by clients then one might prefer to use a database or secret manager (such as vault)
     * to stores the credential directly.
     */
    override fun configure(auth: AuthenticationManagerBuilder?) {
        val encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder()

        auth?.inMemoryAuthentication()?.withUser(clientUsername)?.password(encoder.encode(clientRawPassword))
            ?.roles(CLIENT_ROLE)
    }
}