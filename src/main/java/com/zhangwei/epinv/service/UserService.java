package com.zhangwei.epinv.service;

import com.zhangwei.epinv.dao.UserMapper;
import com.zhangwei.epinv.domain.UserInfo;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;

@Service
public class UserService {

    @Resource
    private UserMapper userMapper;

    public UserInfo findUserByUsername(String username){
        return userMapper.selectByUsername(username);
    }
}
