package com.zhangwei.epinv.jwt;

import org.apache.shiro.authc.AuthenticationToken;

public class JwtToken implements AuthenticationToken {
    private static final long serialVersionUID = 1l;

    private String token;

    private String username;

    public JwtToken(String token){
        this.token = token;
        this.username = JwtUtils.getClaimField(token,"username");
    }

    @Override
    public Object getPrincipal() {
        return username;
    }

    @Override
    public Object getCredentials() {
        return token;
    }
}
