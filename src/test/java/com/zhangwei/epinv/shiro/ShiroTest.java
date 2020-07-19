package com.zhangwei.epinv.shiro;

import org.apache.shiro.crypto.SecureRandomNumberGenerator;
import org.apache.shiro.crypto.hash.SimpleHash;
import org.junit.Test;

public class ShiroTest {

    @Test
    public void testCrypt(){
        String password = "123456";
        String salt = new SecureRandomNumberGenerator().nextBytes().toString();
        int times = 2;
        String alog = "md5";
        String encodedPassword = new SimpleHash(alog,password,salt,times).toString();
        System.out.printf("password : %s\nsalt : %s\nencodedPassword : %s\n",password,salt,encodedPassword);
    }
}
