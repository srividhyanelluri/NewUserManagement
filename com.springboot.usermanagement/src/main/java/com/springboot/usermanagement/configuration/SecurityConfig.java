package com.springboot.usermanagement.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import com.springboot.usermanagement.service.UserManagementService;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity

public class SecurityConfig {
	
	@Bean
//	authentication
	
	public UserDetailsService userDetailsService(PasswordEncoder encoder) {
		
		UserDetails admin= User.withUsername("Tek")
					.password(encoder.encode("1234"))
					.roles("Admin")
					.build();
		
		UserDetails user= User.withUsername("Sri")
				.password(encoder.encode("1234"))
				.roles("USER")
				.build();
		return new InMemoryUserDetailsManager(admin,user);
		
				
	}
	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		
		return http.csrf().disable()
				.authorizeHttpRequests()
				.antMatchers("/users").permitAll()
				.and()
				.authorizeHttpRequests().antMatchers("/users/**").authenticated()
				.and().formLogin().and().build();
			
	}
	
	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
		
	}
	
}
