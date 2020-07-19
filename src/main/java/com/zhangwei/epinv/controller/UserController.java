package com.zhangwei.epinv.controller;

import com.zhangwei.epinv.domain.UserInfo;
import com.zhangwei.epinv.service.UserService;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.Resource;

@RestController
public class UserController {

    @Resource
    public UserService userService;

    @GetMapping("/user")
    @RequiresPermissions("userInfo:view") // 权限管理.
    public UserInfo findUserInfoByUsername(@RequestParam String username) {
        return userService.findUserByUsername(username);
    }
}
