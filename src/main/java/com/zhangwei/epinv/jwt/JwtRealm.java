package com.zhangwei.epinv.jwt;

import com.zhangwei.epinv.domain.UserInfo;
import com.zhangwei.epinv.service.UserService;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;

import javax.annotation.Resource;

public class JwtRealm extends AuthorizingRealm {

    @Resource
    private UserService userService;

    @Override
    public boolean supports(AuthenticationToken token) {
        //只用于处理JwtToken
        //return token instanceof JwtToken;

        //使用这个 realm 来处理 JwtToken 和 UsernamePasswordToken
        return token instanceof JwtToken || token instanceof UsernamePasswordToken;
    }

    //授权
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        UserInfo userInfo = (UserInfo) SecurityUtils.getSubject().getPrincipal();
        SimpleAuthorizationInfo authorizationInfo = new SimpleAuthorizationInfo();
        authorizationInfo.addStringPermission("userInfo:view");
        return authorizationInfo;
    }

    //身份认证
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        //return getAuthenticationInfo1(token);
        return getAuthenticationInfo2(token);
    }

    //身份认证(只处理 JwtToken )
    private AuthenticationInfo getAuthenticationInfo1(AuthenticationToken token) throws AuthenticationException {
        String username = token.getPrincipal().toString();

        UserInfo userInfo = userService.findUserByUsername(username);
        if(userInfo == null){
            return null;
        }
        SimpleAuthenticationInfo authenticationInfo = new SimpleAuthenticationInfo(
                userInfo,
                token.getCredentials(),
                getName()
        );
        return authenticationInfo;
    }

    //身份认证(根据 token 的实际类型进行不同处理)
    private AuthenticationInfo getAuthenticationInfo2(AuthenticationToken token) throws AuthenticationException {
        String username = token.getPrincipal().toString();

        UserInfo userInfo = userService.findUserByUsername(username);
        if(userInfo == null){
            return null;
        }
        SimpleAuthenticationInfo authenticationInfo = null;
        if(token instanceof UsernamePasswordToken){
            authenticationInfo = new SimpleAuthenticationInfo(
                    userInfo,
                    userInfo.getPassword(),
                    ByteSource.Util.bytes(userInfo.getSalt()),
                    getName()
            );
        }
        else if(token instanceof JwtToken){
            authenticationInfo = new SimpleAuthenticationInfo(
                    userInfo,
                    token.getCredentials(),
                    getName()
            );
        }
        return authenticationInfo;
    }
}
