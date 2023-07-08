package com.cos.jwtex01.config;


import com.cos.jwtex01.config.jwt.JwtAuthenticationFilter;
import com.cos.jwtex01.config.jwt.JwtAuthorizationFilter;
import com.cos.jwtex01.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;

@Configuration
@EnableWebSecurity // 시큐리티 활성화 -> 기본 스프링 필터체인에 등록
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	@Autowired
	private UserRepository userRepository;

	@Autowired
	private CorsConfig corsConfig;

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
				.addFilter(corsConfig.corsFilter())
				.csrf().disable() //csrf방지
				.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) // 브라우저에 쿠키와 세션을 저장하지 않겠다
				.and()
				.formLogin().disable()//기본으로 제공하는 login form 안뜨게
				.httpBasic().disable() // id와 pw로 Authorization헤더에 붙여서 내보내는게 Basic방식인데 이걸 disable해야 Bearer로 사용하면서 토큰 방식을 사용해서 더 안전하게 인증헤더에 담아서 보낼 수 있다.

				.addFilter(new JwtAuthenticationFilter(authenticationManager()))
				.addFilter(new JwtAuthorizationFilter(authenticationManager(), userRepository))
				.authorizeRequests()
				.antMatchers("/api/v1/user/**")
				.access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
				.antMatchers("/api/v1/manager/**")
				.access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
				.antMatchers("/api/v1/admin/**")
				.access("hasRole('ROLE_ADMIN')")
				.anyRequest().permitAll();
	}
}






