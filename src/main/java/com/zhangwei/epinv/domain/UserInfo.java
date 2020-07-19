package com.zhangwei.epinv.domain;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@ToString
public class UserInfo {
    private int id;
    private String username;
    private String name;
    private String salt;
    private String password;
}
