package com.zhangwei.epinv.dao;

import com.zhangwei.epinv.domain.UserInfo;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;

@Mapper
public interface UserMapper {

    @Select("SELECT * FROM user WHERE username = #{username}")
    public UserInfo selectByUsername(@Param("username") String username);
}
