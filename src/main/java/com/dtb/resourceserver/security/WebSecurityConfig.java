package com.dtb.resourceserver.security;

import static com.dtb.resourceserver.config.constants.Endpoints.USER_INFO;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
	
	@Value("${security.oauth2.authorization.introspect-uri}")
	private String introspectUri;
	@Value("${security.oauth2.client.id}")
	private String clientId;
	@Value("${security.oauth2.client.secret}")
	private String clientSecret;
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.httpBasic().disable()
			.authorizeRequests(
				authorizeRequests -> authorizeRequests
					.antMatchers(USER_INFO).authenticated()
					.anyRequest().denyAll()	
			)
			.oauth2ResourceServer(
				oauth2ResourceServer -> oauth2ResourceServer
					.opaqueToken(
						opaquetoken -> opaquetoken
							.introspectionUri(introspectUri)
							.introspectionClientCredentials(clientId, clientSecret)							
					)
			);
	}
}
