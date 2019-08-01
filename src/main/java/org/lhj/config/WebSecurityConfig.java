package org.lhj.config;

import lombok.Getter;
import lombok.Setter;
import org.apache.commons.lang3.StringUtils;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import javax.annotation.Resource;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @author 刘洪君
 * @date 2019/8/1 16:29
 */
@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {


    @Resource
    UserDetailsService userDetailsService;

    @Getter
    @Setter
    String[] patterns = new String[]{};

    /**
     * @return 密码加密对象
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //设置 userDetailsService实现
        auth.userDetailsService(userDetailsService);
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }


    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
                // 由于使用的是JWT，我们这里不需要csrf
                .csrf().disable()
                .cors()
                //region 使用token 不需要 http session
                .and()
                .sessionManagement()
                //更改会话创建策略
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                //endregion

                //region 设置哪些请求需要认证 哪些请求不需要
                .and()
                .authorizeRequests()
                // 允许对于网站静态资源的无授权访问
                .antMatchers(HttpMethod.GET, "/", "/*.html", "/favicon.ico", "/**/*.html", "/**/*.css", "/**/*.js").permitAll()
                .antMatchers("/auth").permitAll()
                //ajax 需要 OPTIONS 我们直接开放全部
                .antMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                //之后任何请求都需要认证
                .anyRequest().authenticated()
                //endregion
                .and()
                .logout().permitAll();

        // 添加JWT filter 用来验证token 判断是否认证过
        httpSecurity.addFilterBefore(authenticationTokenFilterBean(), UsernamePasswordAuthenticationFilter.class);

        // 禁用缓存
        httpSecurity.headers().cacheControl();
    }

    @Resource
    JwtTokenProperties jwtTokenProperties;

    @Resource
    JwtTokenUtil jwtTokenUtil;

    /**
     * @return 添加一个拦截器 由我们来处理这个请求是否已经认证
     */
    @Bean
    public OncePerRequestFilter authenticationTokenFilterBean() {
        return new OncePerRequestFilter() {
            /**
             * 所有请求 都会经过这里 通过 @param request 获取 获取在 http header 上的token 处理是否认证业务
             */
            @Override
            protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
                //获取http header 的上面认证token  header key名 通过我们动态配置
                String authHeader = request.getHeader(jwtTokenProperties.getHeader());

                //判断token 不能为 空 && 必须指定字符开头 通过配置
                if (StringUtils.isNotEmpty(authHeader) && authHeader.startsWith(jwtTokenProperties.getTokenHead())) {
                    //去掉token 开头部分
                    final String authToken = authHeader.substring(jwtTokenProperties.getTokenHead().length());

                    //获取到token上面的用户名
                    String username = jwtTokenUtil.getUsernameFromToken(authToken);

                    //通过 spring SecurityContext 取得当前认证信息
                    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

                    if (StringUtils.isNotEmpty(username)) {
                        if (authentication == null) {

                            //对spring SecurityContext的认证信息进行构建
                            UserDetails userDetails = userDetailsService.loadUserByUsername(username);

                            //验证 token 是否跟用户名在数据库的信息匹配 防止用户名伪造
                            //构建一个认证信息对象
                            UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
                                    new UsernamePasswordAuthenticationToken(
                                            userDetails,
                                            null,
                                            userDetails.getAuthorities());

                            //将request 设置进去
                            usernamePasswordAuthenticationToken
                                    .setDetails(new WebAuthenticationDetailsSource().buildDetails(
                                            request));

                            logger.info("authenticated user " + username + ", setting security context");

                            //关键一步 对spring SecurityContext的认证信息进行构建
                            //这一步设置成功 就认定认证成功 之后拦截器都会放行
                            SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);

                        }
                    } else {
                        throw new RuntimeException("未能在 token 上获取到userName");
                    }
                }
                //继续交给下一个过滤器执行
                chain.doFilter(request, response);
            }
        };
    }


    /**
     * 跨越配置
     *
     * @return
     */
    @Bean
    public WebMvcConfigurer corsConfigurer() {
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                registry.addMapping("/**")
                        .allowedOrigins("*")
                        .allowedMethods("PUT", "DELETE", "GET", "POST", "OPTIONS")
                        .allowedHeaders("*")
                        .exposedHeaders(
                                "access-control-allow-headers",
                                "access-control-allow-methods",
                                "access-control-allow-origin",
                                "access-control-max-age",
                                "X-Frame-Options")
                        .allowCredentials(true).maxAge(3600);
            }
        };
    }
}
