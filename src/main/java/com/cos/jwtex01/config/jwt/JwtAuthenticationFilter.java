package com.cos.jwtex01.config.jwt;

import java.io.IOException;
import java.util.Date;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwtex01.config.auth.PrincipalDetails;
import com.cos.jwtex01.dto.LoginRequestDto;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.RequiredArgsConstructor;

//스프링 시큐리티에서 UsernamePasswordAuthenticationFilter가 있음
// login요청해서 username, password 전송하면 (post) UsernamePasswordAuthenticationFilter가 동작함
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter{

	private final AuthenticationManager authenticationManager;

	// login 요청을 하면 로그인 시도를 위해서 실행되는 함수
	// Authentication 객체 만들어서 리턴 => 의존 : AuthenticationManager
	// 인증 요청시에 실행되는 함수 => /login
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {

		// attemptAuthentication() 가 하는 일:
		// 1. username, password를 받아서
		// 2. 정상인지 로그인 시도를 해본다. authenticationManager로 로그인 시도를 하면
		// PrincipalDetailsService가 호출되고 loadUserByUsername() 함수가 실행된다.
		// 3. PrincipalDetails를 세션에 담고(권한 관리를 위해서)
		// 4. JWT토큰을 만들어서 응답해주면 됨.

		System.out.println("JwtAuthenticationFilter : 진입");

		// request에 있는 username과 password를 파싱해서 자바 Object로 받기
		ObjectMapper om = new ObjectMapper();
		LoginRequestDto loginRequestDto = null;
		try {
			loginRequestDto = om.readValue(request.getInputStream(), LoginRequestDto.class);
		} catch (Exception e) {
			e.printStackTrace();
		}

		System.out.println("JwtAuthenticationFilter : "+loginRequestDto);

		// 유저네임패스워드 토큰 생성
		UsernamePasswordAuthenticationToken authenticationToken =
				new UsernamePasswordAuthenticationToken(
						loginRequestDto.getUsername(),
						loginRequestDto.getPassword());

		System.out.println("JwtAuthenticationFilter : 토큰생성완료");

		// authenticate() 함수가 호출 되면 인증 프로바이더가 유저 디테일 서비스의
		// loadUserByUsername(토큰의 첫번째 파라메터) 를 호출하고
		// UserDetails를 리턴받아서 토큰의 두번째 파라메터(credential)과
		// UserDetails(DB값)의 getPassword()함수로 비교해서 동일하면
		// Authentication 객체를 만들어서 필터체인으로 리턴해준다.

		// Tip: 인증 프로바이더의 디폴트 서비스는 UserDetailsService 타입
		// Tip: 인증 프로바이더의 디폴트 암호화 방식은 BCryptPasswordEncoder
		// 결론은 인증 프로바이더에게 알려줄 필요가 없음.
		// PrincipalDetailsService의 loadUserByUsername() 함수가 호출됨
		Authentication authentication =
				authenticationManager.authenticate(authenticationToken);

		// authentication 객체가 session 영역에 저장됨. => 로그인이 되었다는 뜻.
		PrincipalDetails principalDetailis = (PrincipalDetails) authentication.getPrincipal();
		System.out.println("Authentication : "+principalDetailis.getUser().getUsername()); // 출력이 되면 로그인이 정상적으로 됐다는 것.
		// authentication 객체가 session영역에 저장을 해야하고 그 방법이 return 해주면 됨.
		// 리턴의 이유는 권한 관리를 security가 대신 해주기 때문에 편하려고 하는거임.
		// 굳이 JWT토큰을 사용하면서 세션을 만들 이유가 없음. 근데 단지 권한 처리 때문에 session을 넣어준다.
		return authentication;
	}

	// attemptAuthentication 실행 후 인증이 정상적으로 되었으면 successfulAuthentication 함수가 실행됨.
	// JWT Token 생성해서 request 요청한 사용자에게 JWT 를 response 해주면 됨.
	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
											Authentication authResult) throws IOException, ServletException {

		PrincipalDetails principalDetailis = (PrincipalDetails) authResult.getPrincipal();

		// RSA방식은 아니고 Hash암호방식
		String jwtToken = JWT.create()
				.withSubject(principalDetailis.getUsername())
				.withExpiresAt(new Date(System.currentTimeMillis()+JwtProperties.EXPIRATION_TIME))
				.withClaim("id", principalDetailis.getUser().getId())
				.withClaim("username", principalDetailis.getUser().getUsername())
				.sign(Algorithm.HMAC512(JwtProperties.SECRET));

		response.addHeader(JwtProperties.HEADER_STRING, JwtProperties.TOKEN_PREFIX+jwtToken);
	}

}

	/*로그인 정상이면 서버쪽 세션 ID 생성하고 클라이언트 쿠키 세션 ID를 응답.
	요청할때마다 쿠키값 세션 ID를 항상 들고 서버쪽으로 요청하기 때문에 서버는 세션 ID가 유효한지 판단해서 유효하면 인증이 필요한 페이지로 접근하게 하면 됨.

	그런데 JWT방식은
	로그인 정상이면 JWT생성해서 클라이언트 쪽으로 JWT를 응답.
	요청할 때마다 JWT를 가지고 요청을 하는데 서버는 JWT토큰이 유효한지 판단하기 위해서 필터를 만들어야한다.
	*/