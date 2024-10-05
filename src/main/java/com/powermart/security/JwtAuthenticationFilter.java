package com.powermart.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;

@Component
public class JwtAuthenticationFilter extends AbstractGatewayFilterFactory<JwtAuthenticationFilter.Config>{
	
	@Autowired
	JwtService jwtService;
	
	@Autowired
	RouteValidator validator;
	
	public JwtAuthenticationFilter() {
		super(Config.class);
	}
	
	 public static class Config {

	 }
	
	@Override
	public GatewayFilter apply(Config config) {
		
		return ((exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            System.out.println(request.getURI().getPath());
            System.out.println(validator.isSecured.test(request));
			if (validator.isSecured.test(request)) {
            	
            	
                //header contains token or not
                if (!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                    throw new RuntimeException("missing authorization header");
                }

                String authHeader = request.getHeaders().get(HttpHeaders.AUTHORIZATION).get(0);
                if (authHeader != null && authHeader.startsWith("Bearer ")) {
                    authHeader = authHeader.substring(7);
                    System.out.println(authHeader);
                }
                try {
                	String userEmail = jwtService.extractUsername(authHeader);
                	System.out.println(userEmail);
                	System.out.println(jwtService.isTokenValid(authHeader, userEmail));

                } catch (Exception e) {
                    System.out.println("invalid access...!");
                    throw new RuntimeException("un authorized access to application");
                }
            }
            return chain.filter(exchange);
        });
	}

//	@Override
//	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
//			throws ServletException, IOException {
//		
//		 String path = request.getRequestURI();
//
//	        if (path.startsWith("/auth/")) {
//	            filterChain.doFilter(request, response);
//	            return;
//	        }
//		
//		String userEmail = null;
//		
//		String jwt = null;
//		
//		String header = request.getHeader("Authorization");
//		
//		if(header!=null && header.startsWith("Bearer ")) {
//			
//			jwt = header.substring(7);
//			userEmail = jwtService.extractUsername(jwt);
//		}
//		
//		try {
//			
//			Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
//			
//			if(userEmail!=null && authentication == null) {
//				UserDetails userDetails = securityUser.loadUserByUsername(userEmail);
//				
//				 if (jwtService.isTokenValid(jwt, userDetails.getUsername())) {
//	                    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
//	                            userDetails,
//	                            null,
//	                            userDetails.getAuthorities()
//	                    );
//	                    
//	                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
//	                    SecurityContextHolder.getContext().setAuthentication(authToken);
//				 }
//			}
//			filterChain.doFilter(request, response);
//		}
//		catch(Exception e) {
//			System.out.println(e);
//		}
//	}
	
}
	


