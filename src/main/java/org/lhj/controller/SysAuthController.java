package org.lhj.controller;

import org.lhj.config.JwtTokenProperties;
import org.lhj.config.JwtTokenUtil;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.Resource;
import javax.validation.Valid;

/**
 * @author 刘洪君
 * @date 2019/8/1 17:32
 */
@RestController
public class SysAuthController {

    @Resource
    UserDetailsService userDetailsService;

    @Resource
    private AuthenticationManager authenticationManager;

    @Resource
    JwtTokenUtil jwtTokenUtil;
    @Resource
    JwtTokenProperties jwtTokenProperties;

    @RequestMapping("/auth")
    public String auth(@RequestBody @Valid UserAuthModel userAuthModel) {
        UsernamePasswordAuthenticationToken upToken =
                new UsernamePasswordAuthenticationToken(
                        userAuthModel.getUsername(),
                        userAuthModel.getPassword()
                );
        // 账号密码校验
        final Authentication authentication;
        try {
            authentication = authenticationManager.authenticate(upToken);
        } catch (AuthenticationException e) {
            throw new RuntimeException("登陆失败 账号或密码错误");
        }
        //设置认证信息
        SecurityContextHolder.getContext().setAuthentication(authentication);
        // 在安全后重新加载密码，以便我们可以生成令牌
        final UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        //生成token
        final String token = jwtTokenUtil.generateToken(userDetails);
        return jwtTokenProperties.getTokenHead() + " " + token;
    }

    @RequestMapping("/auth/info")
    public Object get() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return authentication.getPrincipal();
    }
}
