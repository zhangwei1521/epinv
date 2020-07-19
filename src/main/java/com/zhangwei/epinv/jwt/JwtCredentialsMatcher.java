package com.zhangwei.epinv.jwt;

import com.zhangwei.epinv.domain.UserInfo;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authc.credential.CredentialsMatcher;
import org.apache.shiro.authc.credential.HashedCredentialsMatcher;

public class JwtCredentialsMatcher implements CredentialsMatcher {

    private HashedCredentialsMatcher hashedCredentialsMatcher;

    public void setHashedCredentialsMatcher(HashedCredentialsMatcher hashedCredentialsMatcher){
        this.hashedCredentialsMatcher = hashedCredentialsMatcher;
    }

    @Override
    public boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) {
        //return matchCredentials1(token,info);
        return matchCredentials2(token,info);
    }

    //只处理 JwtToken
    private boolean matchCredentials1(AuthenticationToken token, AuthenticationInfo info){
        String tokenStr = token.getCredentials().toString();
        UserInfo userInfo = (UserInfo)info.getPrincipals().getPrimaryPrincipal();
        String username = userInfo.getUsername();
        return JwtUtils.verify(tokenStr,username,JwtUtils.SECRET);
    }

    //根据 token 的实际类型进行不同处理
    private boolean matchCredentials2(AuthenticationToken token, AuthenticationInfo info){
        if(token instanceof UsernamePasswordToken){
            //使用 HashedCredentialsMatcher 来处理身份校验
            return hashedCredentialsMatcher.doCredentialsMatch(token,info);
        }
        else if(token instanceof JwtToken){
            String tokenStr = token.getCredentials().toString();
            UserInfo userInfo = (UserInfo)info.getPrincipals().getPrimaryPrincipal();
            String username = userInfo.getUsername();
            return JwtUtils.verify(tokenStr,username,JwtUtils.SECRET);
        }
        return false;
    }
}
