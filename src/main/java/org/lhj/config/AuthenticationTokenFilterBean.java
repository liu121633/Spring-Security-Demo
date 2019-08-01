package org.lhj.config;

import org.apache.commons.lang3.StringUtils;
import org.lhj.sevice.JwtTokenService;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.annotation.Resource;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @author 刘洪君
 * @date 2019/8/1 21:27
 */
public class AuthenticationTokenFilterBean extends OncePerRequestFilter {

    @Resource
    UserDetailsService userDetailsService;
    @Resource
    JwtTokenProperties jwtTokenProperties;

    @Resource
    JwtTokenService jwtTokenService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {
        //获取http header 的上面认证token  header key名 通过我们动态配置
        String authHeader = request.getHeader(jwtTokenProperties.getHeader());

        //判断token 不能为 空 && 必须指定字符开头 通过配置
        if (StringUtils.isNotEmpty(authHeader) && authHeader.startsWith(jwtTokenProperties.getTokenHead())) {
            //去掉token 开头部分
            final String authToken = authHeader.substring(jwtTokenProperties.getTokenHead().length());

            //获取到token上面的用户名
            String username = jwtTokenService.getUsernameFromToken(authToken);

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
}
