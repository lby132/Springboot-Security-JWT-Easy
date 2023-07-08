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
		// 쿠키는 동일 출처 방식이여서 동일한 url이어야 서버와 쿠키를 주고 받을 수 있다.
		// httpOnly 가 있는데 자바스크립트로 보내는걸 막고 http통신만 허용하겠다는건데 자바스크립트에 쿠키를 심어서 보낼 수 있어서 httpOnly 를 true 로 한다.
		http
				.addFilter(corsConfig.corsFilter()) // 컨트롤러 단에 @CrossOrigin을 해주는건 인증이 없을때이고 인증이 필요할땐 시큐리티 필터에 등록한다.
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






